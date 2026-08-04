# src/secopent/interfaces/api/routers/peer_agents.py
"""Peer-agent resource router (W4-A T3).

Exposes the PeerAgentService over HTTP: launch a peer run against an
assessment's scope, list/get/stop runs, and list registered agents. The
service is shared via ``app.state.peer_agent_service`` (constructed in the
composition root behind ``SECOPTENT_PEER_AGENTS_ENABLED``); when it is
``None`` every route returns 503 so the API surface degrades gracefully.

Peer agents are LOW-TRUST discovery sources (spec §4-§5): ``launch`` only
produces candidate Observations that still must pass scope + catalog gates
and oracle N/N verification - it never marks anything Confirmed.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ....application.peer_agents import PeerAgentService
from ....domain.catalog.models import AssetType
from ....domain.common.errors import (
    DomainError,
    DomainValidationError,
)
from ....domain.peer_agents.models import (
    PeerAgentNotRegistered,
    PeerAgentTrustDenied,
    PeerRunScopeViolation,
)
from ....infrastructure.repositories.sqlalchemy_catalog import (
    SqlAlchemyCatalogRepository,
)
from ....infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAssessmentRepository,
    SqlAlchemyScopeRepository,
)
from ..deps import DbSession

router = APIRouter(tags=["peer-agents"])


def _require_service(request: Request) -> PeerAgentService:
    service: PeerAgentService | None = getattr(
        request.app.state, "peer_agent_service", None
    )
    if service is None:
        raise HTTPException(status_code=503, detail="peer agents disabled")
    return service


# -- schemas ---------------------------------------------------------------


class PeerBudgetOut(BaseModel):
    max_wall_seconds: int
    max_cost_units: float


class PeerRunOut(BaseModel):
    id: str
    agent_name: str
    agent_version: str
    assessment_id: str
    targets: tuple[str, ...]
    budget: PeerBudgetOut
    permit_id: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None


class PeerAgentDescriptorOut(BaseModel):
    name: str
    version: str
    license: str
    trust_level: str
    capabilities: tuple[str, ...]
    cost_class: str
    default_budget: PeerBudgetOut
    image_digest: str


class ObservationSummaryOut(BaseModel):
    external_id: str
    asset_identity: str
    title: str
    severity: str
    cwe: tuple[str, ...]


class RejectedFindingOut(BaseModel):
    finding_id: str
    asset: str
    title: str
    reason: str
    detail: str


class PeerRunOutcomeOut(BaseModel):
    run: PeerRunOut
    observations: tuple[ObservationSummaryOut, ...]
    rejected: tuple[RejectedFindingOut, ...]


class PeerRunLaunchRequest(BaseModel):
    agent_name: str
    targets: tuple[str, ...]
    asset_type: AssetType
    actor: str
    permit_id: str


class PeerRunStopRequest(BaseModel):
    actor: str
    reason: str


class PeerRunStopOut(BaseModel):
    run_id: str
    terminated: bool


# -- helpers ---------------------------------------------------------------


def _run_to_out(run) -> PeerRunOut:  # type: ignore[no-untyped-def]
    return PeerRunOut(
        id=run.id,
        agent_name=run.agent_name,
        agent_version=run.agent_version,
        assessment_id=run.assessment_id,
        targets=run.targets,
        budget=PeerBudgetOut(
            max_wall_seconds=run.budget.max_wall_seconds,
            max_cost_units=run.budget.max_cost_units,
        ),
        permit_id=run.permit_id,
        status=run.status.value,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


def _descriptor_to_out(d) -> PeerAgentDescriptorOut:  # type: ignore[no-untyped-def]
    return PeerAgentDescriptorOut(
        name=d.name,
        version=d.version,
        license=d.license,
        trust_level=d.trust_level.value,
        capabilities=d.capabilities,
        cost_class=d.cost_class,
        default_budget=PeerBudgetOut(
            max_wall_seconds=d.default_budget.max_wall_seconds,
            max_cost_units=d.default_budget.max_cost_units,
        ),
        image_digest=d.image_digest,
    )


# -- routes ----------------------------------------------------------------


@router.get("/peer-agents", response_model=tuple[PeerAgentDescriptorOut, ...])
def list_agents(request: Request) -> tuple[PeerAgentDescriptorOut, ...]:
    service = _require_service(request)
    return tuple(_descriptor_to_out(d) for d in service.registry.all())


@router.get(
    "/assessments/{assessment_id}/peer-runs",
    response_model=tuple[PeerRunOut, ...],
)
def list_runs(
    assessment_id: str, request: Request
) -> tuple[PeerRunOut, ...]:
    service = _require_service(request)
    return tuple(_run_to_out(r) for r in service.list_runs(assessment_id))


@router.get("/peer-runs/{run_id}", response_model=PeerRunOut)
def get_run(run_id: str, request: Request) -> PeerRunOut:
    service = _require_service(request)
    run = service.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="peer run not found")
    return _run_to_out(run)


@router.post("/peer-runs/{run_id}/stop", response_model=PeerRunStopOut)
def stop_run(
    run_id: str, payload: PeerRunStopRequest, request: Request
) -> PeerRunStopOut:
    service = _require_service(request)
    if service.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail="peer run not found")
    terminated = service.stop(
        run_id=run_id, actor=payload.actor, reason=payload.reason
    )
    return PeerRunStopOut(run_id=run_id, terminated=terminated)


@router.post(
    "/assessments/{assessment_id}/peer-runs", response_model=PeerRunOutcomeOut
)
def launch_run(
    assessment_id: str,
    payload: PeerRunLaunchRequest,
    request: Request,
    session: DbSession,
) -> PeerRunOutcomeOut:
    """Launch a peer agent against the assessment's approved scope.

    Fetches the assessment's scope snapshot + the latest test catalog from
    the DB, then delegates to ``PeerAgentService.launch``. Domain errors map
    to 4xx; the service only produces candidate Observations (never Confirmed).
    """
    service = _require_service(request)
    assessment = SqlAlchemyAssessmentRepository(session).get(assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    scope = SqlAlchemyScopeRepository(session).get_snapshot(
        assessment.scope_snapshot_id
    )
    if scope is None:
        raise HTTPException(
            status_code=422, detail="assessment scope snapshot missing"
        )
    catalog = SqlAlchemyCatalogRepository(session).latest_catalog()
    if catalog is None:
        raise HTTPException(
            status_code=422, detail="no test catalog available"
        )
    try:
        outcome = service.launch(
            assessment_id=assessment_id,
            agent_name=payload.agent_name,
            targets=payload.targets,
            scope=scope,
            catalog=catalog,
            asset_type=payload.asset_type,
            actor=payload.actor,
            permit_id=payload.permit_id,
        )
    except PeerAgentNotRegistered as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PeerAgentTrustDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except PeerRunScopeViolation as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except DomainValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except DomainError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PeerRunOutcomeOut(
        run=_run_to_out(outcome.run),
        observations=tuple(
            ObservationSummaryOut(
                external_id=o.external_id,
                asset_identity=o.asset_identity,
                title=o.title,
                severity=o.severity.value,
                cwe=o.cwe,
            )
            for o in outcome.observations
        ),
        rejected=tuple(
            RejectedFindingOut(
                finding_id=r.finding.id,
                asset=r.finding.asset,
                title=r.finding.title,
                reason=r.reason.value,
                detail=r.detail,
            )
            for r in outcome.rejected
        ),
    )
