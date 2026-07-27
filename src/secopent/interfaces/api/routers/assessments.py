# src/secopent/interfaces/api/routers/assessments.py
"""Assessments resource router (Phase A P1, W1)."""
from __future__ import annotations

import ipaddress
import uuid

from fastapi import APIRouter, HTTPException

from ....application.assessments import AssessmentService
from ....application.planner import Planner
from ....domain.assessments.models import Assessment, ExecutionPlan
from ....domain.catalog.models import AssetType
from ....domain.common.errors import DomainValidationError
from ....domain.policy.models import ExecutionMode
from ....domain.scope.models import ScopeSnapshot
from ....infrastructure.repositories.sqlalchemy_catalog import (
    SqlAlchemyCatalogRepository,
)
from ....infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAssessmentRepository,
    SqlAlchemyScopeRepository,
)
from ..deps import DbSession
from ..schemas import AssessmentCreate, AssessmentOut, PlanOut, PlanStepOut

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
