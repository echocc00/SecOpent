# src/secopent/interfaces/api/routers/approvals.py
"""Approvals resource router (Phase A P1, W1).

Human approval workflow for assessment plans (decision A):
- ``GET /approvals/pending`` - assessments awaiting a human decision;
- ``GET /approvals/history`` - decided assessments (approved or rejected);
- ``POST /approvals`` - approve (binds plan + scope digest, human-only);
- ``POST /approvals/reject`` - reject with a reason (human-only, audited).

Approval is strictly a human decision (the LLM boundary forbids the model from
approving or rejecting execution). Approve/reject decisions are recorded in the
tamper-evident audit chain.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ....application.assessments import AssessmentPermissionError, AssessmentService
from ....application.audit import AuditService
from ....domain.assessments.models import Approval, AssessmentStatus
from ....domain.common.errors import DomainValidationError
from ....domain.policy.models import RiskClass
from ....infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAssessmentRepository,
    SqlAlchemyAuditRepository,
    SqlAlchemyScopeRepository,
)
from ..deps import DbSession
from ..schemas import (
    ApprovalCreate,
    ApprovalDecisionOut,
    ApprovalOut,
    ApprovalReject,
    ApprovalRequestOut,
)

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


@router.get("/pending", response_model=list[ApprovalRequestOut])
def pending_approvals(session: DbSession) -> list[ApprovalRequestOut]:
    assessment_repo = SqlAlchemyAssessmentRepository(session)
    scope_repo = SqlAlchemyScopeRepository(session)
    result: list[ApprovalRequestOut] = []
    for assessment in assessment_repo.list_all():
        if assessment.status is not AssessmentStatus.AWAITING_APPROVAL:
            continue
        plan = (
            assessment_repo.get_plan(assessment.active_plan_id)
            if assessment.active_plan_id
            else None
        )
        scope = scope_repo.get_snapshot(assessment.scope_snapshot_id)
        result.append(
            ApprovalRequestOut(
                assessment_id=assessment.id,
                project_id=assessment.project_id,
                mode=assessment.mode.value,
                plan_id=assessment.active_plan_id,
                plan_digest=plan.digest if plan else None,
                scope_digest=scope.digest if scope else None,
            )
        )
    return result


@router.get("/history", response_model=list[ApprovalDecisionOut])
def approval_history(session: DbSession) -> list[ApprovalDecisionOut]:
    assessment_repo = SqlAlchemyAssessmentRepository(session)
    audit_repo = SqlAlchemyAuditRepository(session)
    # Rejection reasons live in the audit chain (action="approval.rejected").
    rejections = {
        e.resource_id: e
        for e in audit_repo.list_events()
        if e.action == "approval.rejected"
    }
    result: list[ApprovalDecisionOut] = []
    for assessment in assessment_repo.list_all():
        if assessment.status is AssessmentStatus.APPROVED and assessment.approval_id:
            approval = assessment_repo.get_approval(assessment.approval_id)
            if approval is not None:
                result.append(
                    ApprovalDecisionOut(
                        assessment_id=assessment.id,
                        project_id=assessment.project_id,
                        decision="approved",
                        decided_by=approval.approved_by,
                        approved_risks=sorted(
                            r.value for r in approval.approved_risks
                        ),
                        approved_capabilities=sorted(approval.approved_capabilities),
                        plan_digest=approval.plan_digest,
                        scope_digest=approval.scope_digest,
                    )
                )
        elif assessment.status is AssessmentStatus.REJECTED:
            event = rejections.get(assessment.id)
            result.append(
                ApprovalDecisionOut(
                    assessment_id=assessment.id,
                    project_id=assessment.project_id,
                    decision="rejected",
                    decided_by=str(event.payload.get("rejected_by", "")) if event else "",
                    reason=str(event.payload.get("reason", "")) if event else "",
                )
            )
    return result


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
            actor_role=payload.actor_role,
        )
    except AssessmentPermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DomainValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _to_out(approval)


@router.post("/reject", status_code=201, response_model=ApprovalDecisionOut)
def reject_approval(payload: ApprovalReject, session: DbSession) -> ApprovalDecisionOut:
    service = AssessmentService(SqlAlchemyAssessmentRepository(session))
    try:
        assessment = service.reject(
            assessment_id=payload.assessment_id,
            rejected_by=payload.rejected_by,
            reason=payload.reason,
            actor_role=payload.actor_role,
        )
    except AssessmentPermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DomainValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    AuditService(SqlAlchemyAuditRepository(session)).record(
        actor=payload.rejected_by,
        action="approval.rejected",
        resource_type="assessment",
        resource_id=payload.assessment_id,
        payload={"rejected_by": payload.rejected_by, "reason": payload.reason},
    )
    return ApprovalDecisionOut(
        assessment_id=assessment.id,
        project_id=assessment.project_id,
        decision="rejected",
        decided_by=payload.rejected_by,
        reason=payload.reason,
    )


@router.get("/{approval_id}", response_model=ApprovalOut)
def get_approval(approval_id: str, session: DbSession) -> ApprovalOut:
    approval = SqlAlchemyAssessmentRepository(session).get_approval(approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="approval not found")
    return _to_out(approval)
