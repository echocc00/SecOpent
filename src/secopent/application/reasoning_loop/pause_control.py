# src/secopent/application/reasoning_loop/pause_control.py
"""PauseControlService — human-only pause/resume for a ReasoningLoop
(spec §6.3, v0.7.7 Task 3 + Task 4).

Pause is a *human* action: the loop freezes (``LoopPhase.PAUSED``), then a
human must sign to resume (``LoopPhase.RESUMED``). Agents are rejected from
both operations (403). Whether a resume is allowed is gated by:

* the loop's termination policy's pause budget (``LoopTerminationPolicy.max_pauses``
  via ``pause_budget_exceeded``): if ``pause_attempts + 1`` exceeds the cap,
  the resume is refused with ``PauseBudgetExceeded`` (the orchestrator treats
  that as a forced terminal transition in a LATER task — this service never
  invents a new terminal enum value);
* the human approval port (``LoopApproval.require_resume_approval``), which
  validates the signed resume token and the approved_by/signature presence.

Task 4 (wall-clock credit): the wall-clock time spent in the paused phase must
NOT count toward the loop's budget. On resume, ``credit_budget`` returns a NEW
``LoopBudget`` whose ``wall_seconds_used`` has the pause-period seconds
subtracted (floored at 0). Frozen dataclasses are never mutated — every
transition produces a new ``LoopState`` via ``dataclasses.replace``.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from math import floor
from typing import Any

from ...domain.common.errors import DomainError
from ...domain.reasoning_loop.models import (
    LoopBudget,
    LoopId,
    LoopPhase,
    LoopState,
    LoopTerminationPolicy,
)
from ..ports.audit import AuditRecorder
from ..ports.loop_approval import ApprovalRejected, LoopApproval
from ..ports.loop_state import LoopStateRepository
from .audit import LOOP_PAUSED, LOOP_RESOURCE_TYPE, LOOP_RESUMED


class PauseBudgetExceeded(DomainError):
    """The loop has consumed its maximum human pause cycles (max_pauses).

    The orchestrator wiring (a later task) turns this into a terminal-phase
    transition. This service raises it; it does NOT invent a STOPPED enum.
    """


# Terminal phases: a loop in any of these cannot be paused (it is dead).
_TERMINAL_PHASES: frozenset[LoopPhase] = frozenset(
    {
        LoopPhase.BUDGET_EXHAUSTED,
        LoopPhase.POLICY_BLOCKED,
        LoopPhase.EMERGENCY_STOPPED,
        LoopPhase.COMPLETED,
    }
)

# Phases from which a resume is rejected: a stopped/terminal loop cannot resume.
_RESUME_BLOCKED_PHASES: frozenset[LoopPhase] = frozenset(
    {
        LoopPhase.BUDGET_EXHAUSTED,
        LoopPhase.POLICY_BLOCKED,
        LoopPhase.EMERGENCY_STOPPED,
        LoopPhase.COMPLETED,
    }
)


def credit_budget(budget: LoopBudget, wall_credit_seconds: int | float) -> LoopBudget:
    """Return a NEW LoopBudget with ``wall_seconds_used`` reduced by the pause.

    Pause-period wall-clock must not count toward the loop's hard wall budget,
    so on resume we subtract the paused seconds (``floor(wall_credit_seconds)``)
    from the consumed wall clock, floored at 0. All other fields are copied
    unchanged. Constructed directly (not via ``consume``) because ``consume``
    with a negative value would have ambiguous semantics.
    """
    credit = floor(wall_credit_seconds)
    return LoopBudget(
        max_steps=budget.max_steps,
        max_total_tokens=budget.max_total_tokens,
        max_wall_seconds=budget.max_wall_seconds,
        steps_used=budget.steps_used,
        tokens_used=budget.tokens_used,
        wall_seconds_used=max(0, budget.wall_seconds_used - credit),
    )


def _now_utc() -> datetime:
    return datetime.now(UTC)


class PauseControlService:
    """Pause a loop and resume it under a human-signed approval."""

    def __init__(
        self,
        *,
        state_repo: LoopStateRepository,
        audit: AuditRecorder,
        approval: LoopApproval,
        policy: LoopTerminationPolicy | None = None,
        now_fn: Callable[[], datetime] | None = None,
    ) -> None:
        """Inject the ports + policy + a controllable clock.

        ``policy`` is the authoritative source of ``max_pauses`` (the loop's
        ``policy_snapshot`` is an opaque fingerprint, not the policy object).
        In production the caller supplies the real loop plan's policy;
        it defaults to ``LoopTerminationPolicy.default()``.
        """
        self._state_repo = state_repo
        self._audit = audit
        self._approval = approval
        self._policy = policy or LoopTerminationPolicy.default()
        self._now = now_fn or _now_utc

    def _repo(self, session: Any) -> LoopStateRepository:
        """The state repo for this call.

        When a UoW ``session`` is passed (v0.7.2 hotfix for issue v10), build a
        fresh ``SqlAlchemyLoopStateRepository`` on it so the save commits with
        the caller's transaction; otherwise fall back to the injected repo
        (InMemory tests / read paths that don't need a commit boundary).
        """
        if session is None:
            return self._state_repo
        from ...infrastructure.reasoning_loop.sqlalchemy_state import (
            SqlAlchemyLoopStateRepository,
        )

        return SqlAlchemyLoopStateRepository(session)

    def pause(
        self,
        *,
        loop_id: LoopId,
        actor: str,
        reason: str,
        actor_role: str = "human",
        session: Any = None,
    ) -> LoopState:
        if actor_role == "agent":
            raise ApprovalRejected("pause is human-only (403): agents are rejected")
        state = self._repo(session).get(loop_id)
        if state is None:
            raise LookupError(f"no loop state for {loop_id.value}")
        if state.phase is LoopPhase.PAUSED:
            # Idempotent: already paused. No re-save, no double audit.
            return state
        if state.phase in _TERMINAL_PHASES:
            raise DomainError(
                f"cannot pause a dead loop: phase={state.phase.value} "
                f"(loop {loop_id.value})"
            )
        now = self._now()
        new_state = replace(state, phase=LoopPhase.PAUSED, paused_at=now)
        self._repo(session).save(new_state)
        self._audit.record(
            actor=actor,
            action=LOOP_PAUSED,
            resource_type=LOOP_RESOURCE_TYPE,
            resource_id=loop_id.value,
            payload={
                "reason": reason,
                "phase": LoopPhase.PAUSED.name,
                "context_hash": state.context_hash,
            },
            session=session,
        )
        return new_state

    def resume(
        self,
        *,
        loop_id: LoopId,
        actor: str,
        actor_role: str = "human",
        approved_by: str | None = None,
        signature: str | None = None,
        nonce: str | None = None,
        expires_at: datetime | None = None,
        modified_context: object | None = None,
        session: Any = None,
    ) -> LoopState:
        if actor_role == "agent":
            raise ApprovalRejected("resume is human-only (403): agents are rejected")
        state = self._repo(session).get(loop_id)
        if state is None:
            raise LookupError(f"no loop state for {loop_id.value}")
        if state.phase in _RESUME_BLOCKED_PHASES:
            raise DomainError(
                f"cannot resume a stopped loop: phase={state.phase.value} "
                f"(loop {loop_id.value})"
            )
        # Pause budget: attempts+1 must not exceed max_pauses.
        if self._policy.pause_budget_exceeded(state.pause_attempts + 1):
            raise PauseBudgetExceeded(
                f"loop {loop_id.value} exceeds max_pauses="
                f"{self._policy.max_pauses} (attempts={state.pause_attempts + 1})"
            )
        # Human-signed approval gate.
        self._approval.require_resume_approval(
            loop_id=loop_id,
            actor=actor,
            actor_role=actor_role,
            approved_by=approved_by,
            signature=signature,
            nonce=nonce,
            expires_at=expires_at,
        )
        now = self._now()
        wall_credit = (
            (now - state.paused_at).total_seconds() if state.paused_at is not None else 0.0
        )
        audit_payload: dict[str, object] = {
            "approved_by": approved_by,
            "phase": LoopPhase.RESUMED.name,
            "pause_attempts": state.pause_attempts + 1,
            "wall_credit_seconds": int(wall_credit),
        }
        if modified_context is not None:
            # Task 5 will rewrite the loop context; for now we only record it.
            audit_payload["modified_context"] = modified_context
        new_state = replace(
            state,
            phase=LoopPhase.RESUMED,
            pause_attempts=state.pause_attempts + 1,
            paused_at=None,
            resumed_at=now,
            budget=credit_budget(state.budget, wall_credit),
        )
        self._repo(session).save(new_state)
        self._audit.record(
            actor=actor,
            action=LOOP_RESUMED,
            resource_type=LOOP_RESOURCE_TYPE,
            resource_id=loop_id.value,
            payload=audit_payload,
            session=session,
        )
        return new_state
