# src/secopent/interfaces/api/routers/assessments.py
"""Assessments resource router (Phase A P1, W1)."""
from __future__ import annotations

import ipaddress
import os
import threading
import uuid

from fastapi import APIRouter, HTTPException, Request

from ....application.assessments import AssessmentPermissionError, AssessmentService
from ....application.audit import AuditService
from ....application.emergency_stop import EmergencyStop
from ....application.execution import execute_assessment
from ....application.planner import Planner
from ....domain.assessments.models import Assessment, ExecutionPlan
from ....domain.catalog.models import AssetType
from ....domain.common.errors import DomainValidationError
from ....domain.policy.models import ExecutionMode
from ....domain.scope.models import ScopeSnapshot
from ....infrastructure.adapters.real_scan import RealScanRunner
from ....infrastructure.adapters.step_runner import AdapterStepRunner, ScanContext
from ....infrastructure.repositories.sqlalchemy_catalog import (
    SqlAlchemyCatalogRepository,
)
from ....infrastructure.repositories.sqlalchemy_confirmed import (
    SqlAlchemyConfirmedFindingRepository,
)
from ....infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAssessmentRepository,
    SqlAlchemyAuditRepository,
    SqlAlchemyScopeRepository,
)
from ....infrastructure.repositories.sqlalchemy_findings import (
    SqlAlchemyFindingRepository,
)
from ....infrastructure.safety.emergency_infra import (
    DockerContainerTerminator,
    NullPermitRevoker,
)
from ..deps import DbSession
from ..schemas import (
    AssessmentCreate,
    AssessmentOut,
    EmergencyReportOut,
    PlanOut,
    PlanStepOut,
    StartRequest,
    StopRequest,
)

router = APIRouter(prefix="/assessments", tags=["assessments"])


def _to_out(assessment: Assessment) -> AssessmentOut:
    return AssessmentOut(
        id=assessment.id,
        project_id=assessment.project_id,
        scope_snapshot_id=assessment.scope_snapshot_id,
        mode=assessment.mode.value,
        status=assessment.status.value,
        active_plan_id=assessment.active_plan_id,
        approval_id=assessment.approval_id,
    )


def _plan_to_out(plan: ExecutionPlan) -> PlanOut:
    return PlanOut(
        id=plan.id,
        assessment_id=plan.assessment_id,
        version=plan.version,
        digest=plan.digest,
        steps=[
            PlanStepOut(
                key=s.key,
                runner=s.runner,
                risk=s.risk.value,
                parameters=s.parameters,
                dependencies=list(s.dependencies),
            )
            for s in plan.steps
        ],
    )


def _classify_asset_types(snapshot: ScopeSnapshot) -> list[AssetType]:
    """Map a scope's targets to the catalog asset types they imply.

    URLs imply a WEB_APP; bare IPs/CIDRs imply IP_PORT; bare domains imply a
    WEB_APP; cloud accounts imply CLOUD_ACCOUNT. Order-preserving, de-duped.
    """
    types: list[AssetType] = []

    def add(asset_type: AssetType) -> None:
        if asset_type not in types:
            types.append(asset_type)

    for target in snapshot.include:
        if target.startswith(("http://", "https://")):
            add(AssetType.WEB_APP)
            continue
        try:
            ipaddress.ip_network(target, strict=False)
            add(AssetType.IP_PORT)
        except ValueError:
            add(AssetType.WEB_APP)
    if snapshot.cloud_accounts:
        add(AssetType.CLOUD_ACCOUNT)
    return types


@router.post("", status_code=201, response_model=AssessmentOut)
def create_assessment(
    payload: AssessmentCreate, session: DbSession
) -> AssessmentOut:
    try:
        mode = ExecutionMode(payload.mode)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid mode: {payload.mode}") from exc
    service = AssessmentService(SqlAlchemyAssessmentRepository(session))
    assessment = service.create(
        project_id=payload.project_id,
        scope_snapshot_id=payload.scope_snapshot_id,
        mode=mode,
    )
    return _to_out(assessment)


@router.get("", response_model=list[AssessmentOut])
def list_assessments(
    session: DbSession, project_id: str | None = None
) -> list[AssessmentOut]:
    repo = SqlAlchemyAssessmentRepository(session)
    return [_to_out(a) for a in repo.list_all(project_id)]


@router.get("/{assessment_id}", response_model=AssessmentOut)
def get_assessment(assessment_id: str, session: DbSession) -> AssessmentOut:
    assessment = SqlAlchemyAssessmentRepository(session).get(assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    return _to_out(assessment)


@router.post("/{assessment_id}/plans", status_code=201, response_model=PlanOut)
def generate_plan(
    assessment_id: str,
    session: DbSession,
    catalog_version: str | None = None,
) -> PlanOut:
    """Deterministically generate the execution plan for an assessment (decision F).

    The Planner turns the pinned TestCatalog's required classes for the scope's
    asset types into a risk-tiered DAG (recon before active before intrusive).
    The plan is attached to the assessment, which moves to awaiting_approval.
    Generation is a pure function of catalog + scope - never the LLM.
    """
    assessment_repo = SqlAlchemyAssessmentRepository(session)
    assessment = assessment_repo.get(assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="assessment not found")

    snapshot = SqlAlchemyScopeRepository(session).get_snapshot(
        assessment.scope_snapshot_id
    )
    if snapshot is None:
        raise HTTPException(status_code=404, detail="scope snapshot not found")

    catalog_repo = SqlAlchemyCatalogRepository(session)
    catalog = (
        catalog_repo.get_catalog_by_version(catalog_version)
        if catalog_version
        else catalog_repo.latest_catalog()
    )
    if catalog is None:
        raise HTTPException(status_code=409, detail="no test catalog available")

    asset_types = _classify_asset_types(snapshot)
    plan = Planner(catalog).generate(
        plan_id=f"plan-{uuid.uuid4().hex[:12]}",
        assessment_id=assessment_id,
        asset_types=asset_types,
    )
    if not plan.steps:
        raise HTTPException(
            status_code=422,
            detail="no required test classes for the scope's asset types",
        )

    service = AssessmentService(assessment_repo)
    try:
        updated = service.attach_plan(assessment_id, plan.steps)
    except DomainValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    created = assessment_repo.get_plan(updated.active_plan_id or "")
    if created is None:  # pragma: no cover - attach_plan always sets active_plan_id
        raise HTTPException(status_code=500, detail="plan was not persisted")
    return _plan_to_out(created)


def _production_step_runner(scope: ScopeSnapshot) -> AdapterStepRunner:
    """Build the real AdapterStepRunner over RealScanRunner for an engagement."""
    # nuclei templates: mount the operator-downloaded template dir so scans use
    # curated templates instead of the built-in set (which needs network to
    # fetch). Offline/NAS deployments set SECOPTENT_NUCLEI_TEMPLATE_DIR.
    template_dir = os.environ.get("SECOPTENT_NUCLEI_TEMPLATE_DIR", "").strip()
    # Full HTTP template set (13k templates) needs 6-10 min on a weak NAS; the
    # prior 180s cut scans short and even 600s was insufficient. Default 1800s
    # (30 min) covers it; override via SECOPTENT_SCAN_TIMEOUT for slower hosts.
    try:
        scan_timeout = int(os.environ.get("SECOPTENT_SCAN_TIMEOUT", "1800"))
    except ValueError:
        scan_timeout = 1800
    return AdapterStepRunner(
        RealScanRunner(default_timeout=scan_timeout),
        ScanContext(
            targets=scope.include,
            template_host_dir=template_dir or None,
        ),
    )


def _orchestrator_max_workers() -> int:
    """Same-layer step concurrency (NAS hardening, v0.1.5).

    Default 1 (serial) is NAS-safe: weak CPUs (N100/Celeron) and limited RAM
    OOM when multiple adapter containers overlap. Raise on a strong host via
    SECOPTENT_MAX_PARALLEL_STEPS=N (e.g. 4 on a 16GB workstation).
    """
    try:
        return max(1, int(os.environ.get("SECOPTENT_MAX_PARALLEL_STEPS", "1")))
    except ValueError:
        return 1


@router.post("/{assessment_id}/start", response_model=AssessmentOut)
def start_assessment(
    assessment_id: str, payload: StartRequest, request: Request, session: DbSession
) -> AssessmentOut:
    """Trigger assessment execution: APPROVED -> QUEUED, then run in background.

    Human-only (triggers real scans). The Orchestrator runs in a daemon thread
    (``application.execution.execute_assessment``); this endpoint returns
    immediately with status=QUEUED. Progress streams via the SSE endpoint
    (``GET /assessments/{id}/events``) which polls ``assessment.status``.
    Findings are persisted with ``assessment_id`` as they are correlated.
    """
    assessment_repo = SqlAlchemyAssessmentRepository(session)
    service = AssessmentService(assessment_repo)
    try:
        assessment = service.start(assessment_id, actor_role=payload.actor_role)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DomainValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except AssessmentPermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    # The background thread owns its own session; the request session is closed
    # after the response, so we reconstruct repos against app.state.db there.
    db = request.app.state.db
    # Security components (W2-A T6): shared singletons from the composition root.
    emergency_stop = getattr(request.app.state, "emergency_stop", None)
    permit_signer = getattr(request.app.state, "permit_signer", None)
    permit_registry = getattr(request.app.state, "permit_registry", None)
    permit_verifier = getattr(request.app.state, "permit_verifier", None)
    scope_enforcer = getattr(request.app.state, "scope_enforcer", None)
    audit_chain = getattr(request.app.state, "audit_chain", None)
    egress_guard = getattr(request.app.state, "egress_guard", None)
    nft_scope_enforcer = getattr(request.app.state, "nft_scope_enforcer", None)
    oracle = getattr(request.app.state, "oracle", None)

    def _run() -> None:
        thread = threading.current_thread()
        # Register so SIGTERM grace (lifespan shutdown) can drain this thread.
        active = getattr(request.app.state, "active_executions", None)
        lock = getattr(request.app.state, "active_executions_lock", None)
        if active is not None and lock is not None:
            with lock:
                active.add(thread)
        bg_session = db.open_session()
        try:
            # Compute coverage inputs (catalog + asset types) for the report.
            catalog = SqlAlchemyCatalogRepository(bg_session).latest_catalog()
            assessment = SqlAlchemyAssessmentRepository(bg_session).get(assessment_id)
            scope = (
                SqlAlchemyScopeRepository(bg_session).get_snapshot(
                    assessment.scope_snapshot_id
                )
                if assessment
                else None
            )
            asset_types = tuple(_classify_asset_types(scope)) if scope else ()
            execute_assessment(
                assessment_id=assessment_id,
                assessment_repo=SqlAlchemyAssessmentRepository(bg_session),
                scope_repo=SqlAlchemyScopeRepository(bg_session),
                finding_repo=SqlAlchemyFindingRepository(bg_session),
                audit_repo=SqlAlchemyAuditRepository(bg_session),
                step_runner_factory=_production_step_runner,
                catalog=catalog,
                asset_types=asset_types,
                max_workers=_orchestrator_max_workers(),
                emergency_stop=emergency_stop,
                permit_signer=permit_signer,
                permit_registry=permit_registry,
                permit_verifier=permit_verifier,
                scope_enforcer=scope_enforcer,
                egress_guard=egress_guard,
                nft_scope_enforcer=nft_scope_enforcer,
                audit_chain=audit_chain,
                oracle=oracle,
                confirmed_finding_repo=(
                    SqlAlchemyConfirmedFindingRepository(bg_session)
                    if oracle is not None
                    else None
                ),
            )
            bg_session.commit()
        except Exception:
            bg_session.rollback()
            raise
        finally:
            bg_session.close()
            if active is not None and lock is not None:
                with lock:
                    active.discard(thread)

    threading.Thread(target=_run, daemon=False, name=f"assess-{assessment_id}").start()
    return _to_out(assessment)


@router.post("/{assessment_id}/stop", response_model=EmergencyReportOut)
def emergency_stop(
    assessment_id: str, payload: StopRequest, request: Request, session: DbSession
) -> EmergencyReportOut:
    """Trigger the emergency stop for an assessment (human-only, §12).

    Revokes unused permits, terminates active execution containers, preserves
    evidence, and writes a high-priority audit event. Agent callers are
    rejected (403) - the kill switch is a human-only action (LLM boundary).
    """
    if payload.actor_role != "human":
        raise HTTPException(
            status_code=403, detail="emergency stop is human-only (LLM boundary)"
        )
    if SqlAlchemyAssessmentRepository(session).get(assessment_id) is None:
        raise HTTPException(status_code=404, detail="assessment not found")

    # Use the shared kill switch from the composition root (W2-A T6) so the
    # background executor sees the triggered flag and refuses new assessments.
    stop = getattr(request.app.state, "emergency_stop", None)
    if stop is None:
        # Fallback (older app without composition root): construct per-call.
        stop = EmergencyStop(
            permit_revoker=NullPermitRevoker(),
            container_terminator=DockerContainerTerminator(),
            audit=AuditService(SqlAlchemyAuditRepository(session)),
        )
    report = stop.trigger(actor=payload.actor, reason=payload.reason)
    return EmergencyReportOut(
        triggered=report.triggered,
        revoked_permits=report.revoked_permits,
        terminated_containers=report.terminated_containers,
        evidence_preserved=report.evidence_preserved,
        actor=report.actor,
        reason=report.reason,
    )
