# src/secopent/interfaces/api/routers/approvals.py
"""Approvals resource router (Phase A P1, W1).

Records a human approval binding the assessment's active plan digest + scope
digest. Approval is strictly a human decision (the LLM boundary forbids the
model from approving execution). The router resolves the scope digest from the
assessment's scope snapshot and delegates to ``AssessmentService.approve``.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ....application.assessments import AssessmentService
from ....domain.assessments.models import Approval
from ....domain.common.errors import DomainValidationError
from ....domain.policy.models import RiskClass
from ....infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAssessmentRepository,
    SqlAlchemyScopeRepository,
)
from ..deps import DbSession
from ..schemas import ApprovalCreate, ApprovalOut

router = APIRouter(prefix="/approvals", tags=["approvals"])


def _to_out(approval: Approval) -> ApprovalOut:
    return ApprovalOut(
        id=approval.id,
        assessment_id=approval.assessment_id,
        plan_digest=approval.plan_digest,
        scope_digest=approval.scope_digest,
        mode=approval.mode.value,
        approved_risks=sorted(r.value for r in approval.approved_risks),
        approved_capabilities=sorted(approval.approved_capabilities),
        approved_by=approval.approved_by,
        digest=approval.digest,
    )


@router.post("", status_code=201, response_model=ApprovalOut)
def create_approval(payload: ApprovalCreate, session: DbSession) -> ApprovalOut:
    assessment_repo = SqlAlchemyAssessmentRepository(session)
    assessment = assessment_repo.get(payload.assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="assessment not found")

    snapshot = SqlAlchemyScopeRepository(session).get_snapshot(
        assessment.scope_snapshot_id
    )
    if snapshot is None:
        raise HTTPException(status_code=404, detail="scope snapshot not found")

    try:
        approved_risks = frozenset(RiskClass(r) for r in payload.approved_risks)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid risk: {exc}") from exc

    service = AssessmentService(assessment_repo)
    try:
        approval = service.approve(
            assessment_id=payload.assessment_id,
            approved_by=payload.approved_by,
            approved_risks=approved_risks,
            approved_capabilities=frozenset(payload.approved_capabilities),
            scope_digest=snapshot.digest,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DomainValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _to_out(approval)


@router.get("/{approval_id}", response_model=ApprovalOut)
def get_approval(approval_id: str, session: DbSession) -> ApprovalOut:
    approval = SqlAlchemyAssessmentRepository(session).get_approval(approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="approval not found")
    return _to_out(approval)
