# src/secopent/interfaces/api/routers/plans.py
"""Plans resource router (Phase A P1, W1).

A plan is a deterministic execution DAG. The router accepts an explicit step
list and delegates to ``AssessmentService.attach_plan``, which validates the DAG
(unique keys, no dependency cycle) and moves the assessment to
``awaiting_approval``. The Planner (application/planner.py) generates these
steps from the pinned TestCatalog; the router is the transport for a
caller-supplied plan.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ....application.assessments import AssessmentService
from ....domain.assessments.models import ExecutionPlan, PlanStep
from ....domain.common.errors import DomainValidationError
from ....domain.policy.models import RiskClass
from ....infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAssessmentRepository,
)
from ..deps import DbSession
from ..schemas import PlanCreate, PlanOut, PlanStepOut

router = APIRouter(prefix="/plans", tags=["plans"])


def _to_out(plan: ExecutionPlan) -> PlanOut:
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


@router.post("", status_code=201, response_model=PlanOut)
def create_plan(payload: PlanCreate, session: DbSession) -> PlanOut:
    try:
        steps = tuple(
            PlanStep(
                key=s.key,
                runner=s.runner,
                risk=RiskClass(s.risk),
                parameters=s.parameters,
                dependencies=tuple(s.dependencies),
            )
            for s in payload.steps
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid step: {exc}") from exc

    repo = SqlAlchemyAssessmentRepository(session)
    service = AssessmentService(repo)
    try:
        updated = service.attach_plan(payload.assessment_id, steps)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DomainValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    plan = repo.get_plan(updated.active_plan_id or "")
    if plan is None:  # pragma: no cover - attach_plan always sets active_plan_id
        raise HTTPException(status_code=500, detail="plan was not persisted")
    return _to_out(plan)


@router.get("/{plan_id}", response_model=PlanOut)
def get_plan(plan_id: str, session: DbSession) -> PlanOut:
    plan = SqlAlchemyAssessmentRepository(session).get_plan(plan_id)
    if plan is None:
        raise HTTPException(status_code=404, detail="plan not found")
    return _to_out(plan)
