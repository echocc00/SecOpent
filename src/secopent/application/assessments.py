from __future__ import annotations

import uuid
from dataclasses import replace
from typing import TYPE_CHECKING

from ..domain.assessments.models import (
    Approval,
    Assessment,
    AssessmentStatus,
    ControlState,
    ExecutionPlan,
    PlanStep,
)
from ..domain.assessments.transitions import assert_transition
from ..domain.common.canonical import utc_now
from ..domain.common.errors import DomainError, DomainValidationError
from ..domain.policy.models import ExecutionMode, RiskClass
from .ports.repositories import AssessmentRepository
from .ports.repositories import ScopeRepository as _ScopeRepoPort

if TYPE_CHECKING:
    from .grants import GrantService


class AssessmentPermissionError(DomainError):
    """Raised when an agent attempts a human-only action (approve/reject)."""


class AssessmentService:
    def __init__(
        self,
        repo: AssessmentRepository,
        *,
        scope_repo: _ScopeRepoPort | None = None,
        grant_service: GrantService | None = None,
    ) -> None:
        self._repo = repo
        self._scope_repo = scope_repo
        self._grant_service = grant_service

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
        # v0.3.0 T7: guard gap fix - previously ANY status could (re-)attach a
        # plan; only DRAFT / AWAITING_APPROVAL (re-plan) may.
        assert_transition(assessment.status, AssessmentStatus.AWAITING_APPROVAL)
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
        grant_id: str | None = None,
    ) -> Approval:
        """Record a human approval against the assessment's active plan.

        The approval binds the plan digest (from the active plan) and the
        scope digest (supplied by the caller, which owns the scope lookup) so
        the approved execution is pinned to exactly the plan + scope the
        approver reviewed. On success the assessment moves to APPROVED and its
        ``approval_id`` is set. Approval is a human decision - never the LLM.

        With ``grant_id`` (agent path, v0.6.0): the grant must authorize the
        assessment's scope + plan; the recorded approver becomes
        ``grant:<grant_id>`` (the caller-supplied ``approved_by`` is
        overridden - an agent can never stamp its own name on an approval).
        """
        if grant_id is not None:
            self._authorize_via_grant(grant_id, assessment_id)
            approved_by = f"grant:{grant_id}"
        else:
            self._require_human(actor_role)
        assessment = self._repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        if assessment.active_plan_id is None:
            raise DomainValidationError("assessment has no plan to approve")
        # v0.3.0 T7: guard gap fix - previously an assessment could be
        # approved from any status (e.g. REJECTED); only AWAITING_APPROVAL may.
        assert_transition(assessment.status, AssessmentStatus.APPROVED)
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
        assert_transition(assessment.status, AssessmentStatus.REJECTED)
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

    def _authorize_via_grant(self, grant_id: str, assessment_id: str) -> None:
        """Approve/start via grant: authorize scope + plan, else raise.

        Both approve and start re-check the grant at their own moment - start
        re-validates because a grant can be revoked between approval and start.
        Degrades safe: a service built without a scope repo or grant service
        can never authorize via grant.
        """
        if self._grant_service is None:
            raise AssessmentPermissionError("grant service not configured")
        if self._scope_repo is None:
            raise AssessmentPermissionError(
                "scope repository not configured for grant approval"
            )
        assessment = self._repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        scope = self._scope_repo.get_snapshot(assessment.scope_snapshot_id)
        if scope is None:
            raise DomainValidationError("assessment scope not found")
        plan = self._repo.get_plan(assessment.active_plan_id) if assessment.active_plan_id else None
        steps = tuple(plan.steps) if plan is not None else ()
        decision = self._grant_service.authorize(
            grant_id, scope, steps, now=utc_now()
        )
        if not decision.allowed:
            raise AssessmentPermissionError(
                f"grant denied: {decision.reason}"
            )

    def start(
        self,
        assessment_id: str,
        *,
        actor_role: str = "human",
        grant_id: str | None = None,
    ) -> Assessment:
        """Human-only: APPROVED -> QUEUED, triggering real execution.

        Requires an approved plan + approval; the actual scan runs in a
        background executor (see ``application.execution``). Start is a human
        decision - never the LLM. With ``grant_id`` (agent path, v0.6.0) the
        grant must still authorize the scope + plan at START time - a revoked
        or expired grant cannot start a previously-approved run.
        """
        if grant_id is not None:
            self._authorize_via_grant(grant_id, assessment_id)
        else:
            self._require_human(actor_role)
        assessment = self._repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        assert_transition(assessment.status, AssessmentStatus.QUEUED)
        if not assessment.active_plan_id:
            raise DomainValidationError("assessment has no plan to execute")
        if not assessment.approval_id:
            raise DomainValidationError("assessment has no approval")
        updated = assessment.start(
            plan_id=assessment.active_plan_id, approval_id=assessment.approval_id
        )
        self._repo.add(updated)
        return updated

    def mark_running(self, assessment_id: str) -> Assessment:
        """QUEUED -> RUNNING (called by the background executor)."""
        assessment = self._repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        assert_transition(assessment.status, AssessmentStatus.RUNNING)
        updated = replace(assessment, status=AssessmentStatus.RUNNING)
        self._repo.add(updated)
        return updated

    def complete(self, assessment_id: str) -> Assessment:
        """RUNNING -> COMPLETED (called by the background executor on success)."""
        assessment = self._repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        assert_transition(assessment.status, AssessmentStatus.COMPLETED)
        updated = replace(assessment, status=AssessmentStatus.COMPLETED)
        self._repo.add(updated)
        return updated

    def fail(self, assessment_id: str, reason: str) -> Assessment:
        """RUNNING -> FAILED (called by the background executor on failure)."""
        assessment = self._repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        assert_transition(assessment.status, AssessmentStatus.FAILED)
        updated = replace(assessment, status=AssessmentStatus.FAILED)
        self._repo.add(updated)
        return updated

    # --- MCP control-plane orchestration (M4 §13; agent-callable) ----------
    # status/pause/resume/cancel are read/control-plane operations, NOT the
    # human-gated approve/reject/start surface. Each control move writes a
    # durable signal (``control``) alongside the status transition; the
    # executor thread consumes the signal at step boundaries (M4): a paused
    # run finishes its in-flight step then issues no new work (remaining jobs
    # stay READY for a resume drain); a cancelled run abandons the remaining
    # jobs. The status column is the source of truth the executor respects.

    def status(self, assessment_id: str) -> Assessment:
        """Read-only status probe; raises LookupError when not found."""
        assessment = self._repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        return assessment

    @staticmethod
    def _set_control(
        assessment: Assessment, target: AssessmentStatus, signal: ControlState
    ) -> Assessment:
        """Status transition + control signal in one atomic domain update."""
        assert_transition(assessment.status, target)
        return replace(
            assessment, status=target, control=signal,
        )

    def pause(self, assessment_id: str) -> Assessment:
        """RUNNING -> PAUSED; requests the executor to stop at the next step."""
        assessment = self._repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        updated = self._set_control(
            assessment, AssessmentStatus.PAUSED, ControlState.PAUSE_REQUESTED
        )
        self._repo.add(updated)
        return updated

    def resume(self, assessment_id: str) -> Assessment:
        """PAUSED -> RUNNING; requests a drain restart for remaining jobs."""
        assessment = self._repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        updated = self._set_control(
            assessment, AssessmentStatus.RUNNING, ControlState.RESUME_REQUESTED
        )
        self._repo.add(updated)
        return updated

    def cancel(self, assessment_id: str) -> Assessment:
        """QUEUED/RUNNING/PAUSED -> CANCELLED; requests container termination."""
        assessment = self._repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        updated = self._set_control(
            assessment, AssessmentStatus.CANCELLED, ControlState.CANCEL_REQUESTED
        )
        self._repo.add(updated)
        return updated
