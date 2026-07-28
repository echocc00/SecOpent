from __future__ import annotations

import uuid
from dataclasses import replace

from ..domain.assessments.models import (
    Approval,
    Assessment,
    AssessmentStatus,
    ExecutionPlan,
    PlanStep,
)
from ..domain.common.errors import DomainError, DomainValidationError
from ..domain.policy.models import ExecutionMode, RiskClass
from .ports.repositories import AssessmentRepository


class AssessmentPermissionError(DomainError):
    """Raised when an agent attempts a human-only action (approve/reject)."""


class AssessmentService:
    def __init__(self, repo: AssessmentRepository) -> None:
        self._repo = repo

    def create(self, *, project_id: str, scope_snapshot_id: str,
               mode: ExecutionMode) -> Assessment:
        assessment = Assessment.create(
            assessment_id=f"asm-{uuid.uuid4().hex[:12]}",
            project_id=project_id, scope_snapshot_id=scope_snapshot_id, mode=mode,
        )
        self._repo.add(assessment)
        return assessment

    def attach_plan(self, assessment_id: str, steps: tuple[PlanStep, ...]) -> Assessment:
        assessment = self._repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        plan = ExecutionPlan.create(
            plan_id=f"plan-{uuid.uuid4().hex[:12]}",
            assessment_id=assessment_id, version=1, steps=steps,
        )
        self._repo.save_plan(plan)
        updated = replace(
            assessment,
            status=AssessmentStatus.AWAITING_APPROVAL,
            active_plan_id=plan.id,
        )
        self._repo.add(updated)
        return updated

    def approve(
        self,
        *,
        assessment_id: str,
        approved_by: str,
        approved_risks: frozenset[RiskClass],
        approved_capabilities: frozenset[str],
        scope_digest: str,
        actor_role: str = "human",
    ) -> Approval:
        """Record a human approval against the assessment's active plan.

        The approval binds the plan digest (from the active plan) and the
        scope digest (supplied by the caller, which owns the scope lookup) so
        the approved execution is pinned to exactly the plan + scope the
        approver reviewed. On success the assessment moves to APPROVED and its
        ``approval_id`` is set. Approval is a human decision - never the LLM.
        """
        self._require_human(actor_role)
        assessment = self._repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        if assessment.active_plan_id is None:
            raise DomainValidationError("assessment has no plan to approve")
        plan = self._repo.get_plan(assessment.active_plan_id)
        if plan is None:
            raise LookupError("active plan not found")
        approval = Approval.create(
            approval_id=f"apr-{uuid.uuid4().hex[:12]}",
            assessment_id=assessment_id,
            plan_digest=plan.digest,
            scope_digest=scope_digest,
            mode=assessment.mode,
            approved_risks=approved_risks,
            approved_capabilities=approved_capabilities,
            approved_by=approved_by,
        )
        self._repo.save_approval(approval)
        updated = replace(
            assessment,
            status=AssessmentStatus.APPROVED,
            approval_id=approval.id,
        )
        self._repo.add(updated)
        return approval

    def reject(
        self,
        *,
        assessment_id: str,
        rejected_by: str,
        reason: str,
        actor_role: str = "human",
    ) -> Assessment:
        """Human-only: reject an awaiting-approval assessment (with a reason).

        Only assessments in AWAITING_APPROVAL may be rejected; a non-empty
        reason is required (it is recorded in the audit chain by the caller).
        Rejection is a human decision - never the LLM.
        """
        self._require_human(actor_role)
        assessment = self._repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        if assessment.status is not AssessmentStatus.AWAITING_APPROVAL:
            raise DomainValidationError(
                f"assessment {assessment_id} is not awaiting approval "
                f"(status={assessment.status.value})"
            )
        if not reason.strip():
            raise DomainValidationError("rejection reason must be non-empty")
        updated = replace(assessment, status=AssessmentStatus.REJECTED)
        self._repo.add(updated)
        return updated

    @staticmethod
    def _require_human(actor_role: str) -> None:
        if actor_role == "agent":
            raise AssessmentPermissionError(
                "agents cannot approve or reject assessments (human-only action)"
            )
        if actor_role != "human":
            raise AssessmentPermissionError(f"unknown actor role: {actor_role!r}")
