# src/secopent/interfaces/api/routers/assessments.py
"""Assessments resource router (Phase A P1, W1)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ....application.assessments import AssessmentService
from ....domain.assessments.models import Assessment
from ....domain.policy.models import ExecutionMode
from ....infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAssessmentRepository,
)
from ..deps import DbSession
from ..schemas import AssessmentCreate, AssessmentOut

router = APIRouter(prefix="/assessments", tags=["assessments"])


def _to_out(assessment: Assessment) -> AssessmentOut:
    return AssessmentOut(
        id=assessment.id,
        project_id=assessment.project_id,
        scope_snapshot_id=assessment.scope_snapshot_id,
        mode=assessment.mode.value,
        status=assessment.status.value,
    )


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
