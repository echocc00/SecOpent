# tests/application/reasoning_loop/test_pause_control.py
"""PauseControlService — human-only pause/resume (spec §6.3, v0.7.7 Task 3)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from secopent.application.ports.loop_approval import (
    ApprovalRejected,
    ApprovalRequired,
    validate_loop_approval_params,
)
from secopent.application.reasoning_loop.audit import LOOP_PAUSED, LOOP_RESUMED
from secopent.application.reasoning_loop.pause_control import (
    PauseBudgetExceeded,
    PauseControlService,
)
from secopent.domain.reasoning_loop.models import (
    LoopBudget,
    LoopId,
    LoopPhase,
    LoopState,
    LoopTerminationPolicy,
)

T0 = datetime(2026, 8, 19, 12, 0, 0, tzinfo=UTC)


@dataclass
class FakeStateRepo:
    """In-memory LoopStateRepository with save counting."""

    states: dict[str, LoopState] = field(default_factory=dict)
    save_count: int = 0

    def get(self, loop_id: LoopId) -> LoopState | None:
        return self.states.get(loop_id.value)

    def save(self, state: LoopState) -> None:
        self.save_count += 1
        self.states[state.loop_id.value] = state


@dataclass
class FakeAudit:
    """AuditRecorder that accumulates records; satisfies the Protocol."""

    events: list[dict[str, object]] = field(default_factory=list)

    def record(
        self,
        *,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        payload: dict[str, object],
        session: object = None,
    ) -> object:
        self.events.append(
            {
                "actor": actor,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "payload": payload,
            }
        )
        return None


class FakeLoopApproval:
    """Applies validate_loop_approval_params + stores the last call for
    assertion. Satisfies the LoopApproval Protocol."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def require_resume_approval(
        self,
        *,
        loop_id: object,
        actor: str,
        actor_role: str,
        approved_by: str | None = None,
        signature: str | None = None,
        nonce: str | None = None,
        expires_at: object | None = None,
    ) -> None:
        self.calls.append(
            {
                "loop_id": loop_id,
                "actor": actor,
                "actor_role": actor_role,
                "approved_by": approved_by,
                "signature": signature,
                "nonce": nonce,
                "expires_at": expires_at,
            }
        )
        validate_loop_approval_params(
            actor_role=actor_role,
            approved_by=approved_by,
            signature=signature,
        )


def _loop(
    *,
    phase: LoopPhase = LoopPhase.RUNNING,
    pause_attempts: int = 0,
    paused_at: datetime | None = None,
    budget: LoopBudget | None = None,
) -> LoopState:
    budget = budget or LoopBudget.default()
    return LoopState(
        loop_id=LoopId.new(),
        assessment_id="assessment-1",
        phase=phase,
        policy_snapshot="policy-snap",
        budget=budget,
        context_hash="ctx-hash",
        catalog_required_remaining=frozenset(),
        catalog_required_executed=frozenset(),
        consecutive_no_signal=0,
        consecutive_policy_rejected=0,
        started_at=T0,
        last_step_at=T0,
        pause_attempts=pause_attempts,
        paused_at=paused_at,
    )


def _harness(
    *,
    policy: LoopTerminationPolicy | None = None,
    now: datetime = T0,
):
    repo = FakeStateRepo()
    audit = FakeAudit()
    approval = FakeLoopApproval()
    service = PauseControlService(
        state_repo=repo,
        audit=audit,
        approval=approval,
        policy=policy or LoopTerminationPolicy.default(),
        now_fn=lambda: now,
    )
    return repo, audit, approval, service


def test_pause_sets_paused_and_audits() -> None:
    repo, audit, _approval, service = _harness()
    loop = _loop()
    repo.save(loop)

    result = service.pause(loop_id=loop.loop_id, actor="alice", reason="review")

    assert result.phase is LoopPhase.PAUSED
    assert result.paused_at == T0
    assert len(audit.events) == 1
    ev = audit.events[0]
    assert ev["action"] == LOOP_PAUSED
    assert ev["actor"] == "alice"
    assert ev["resource_id"] == loop.loop_id.value
    assert ev["payload"]["reason"] == "review"
    assert ev["payload"]["phase"] == "PAUSED"
    assert ev["payload"]["context_hash"] == "ctx-hash"


def test_pause_agent_denied() -> None:
    repo, _audit, _approval, service = _harness()
    loop = _loop()
    repo.save(loop)

    with pytest.raises(ApprovalRejected):
        service.pause(loop_id=loop.loop_id, actor="agent-1", reason="x", actor_role="agent")


def test_pause_idempotent_if_already_paused() -> None:
    repo, audit, _approval, service = _harness()
    loop = _loop(phase=LoopPhase.PAUSED, paused_at=T0)
    repo.save(loop)

    result = service.pause(loop_id=loop.loop_id, actor="alice", reason="again")

    assert result.phase is LoopPhase.PAUSED
    assert result.paused_at == T0
    # Idempotent: no extra audit, no extra save.
    assert len(audit.events) == 0
    assert repo.save_count == 1  # only the initial manual save


def test_pause_rejected_when_terminal() -> None:
    repo, _audit, _approval, service = _harness()
    loop = _loop(phase=LoopPhase.BUDGET_EXHAUSTED)
    repo.save(loop)

    with pytest.raises(Exception) as exc_info:
        service.pause(loop_id=loop.loop_id, actor="alice", reason="x")
    assert "dead loop" in str(exc_info.value)


def test_resume_requires_human_approval() -> None:
    repo, _audit, _approval, service = _harness()
    loop = _loop(phase=LoopPhase.PAUSED, paused_at=T0)  # type: ignore[arg-type]
    repo.save(loop)

    # Agent role -> ApprovalRejected.
    with pytest.raises(ApprovalRejected):
        service.resume(loop_id=loop.loop_id, actor="agent-1", actor_role="agent")

    # Missing signature -> ApprovalRequired.
    with pytest.raises(ApprovalRequired):
        service.resume(loop_id=loop.loop_id, actor="alice", approved_by="bob")


def test_resume_sets_resumed_then_audits() -> None:
    repo, audit, approval, service = _harness()
    loop = _loop(phase=LoopPhase.PAUSED, paused_at=T0)  # type: ignore[arg-type]
    repo.save(loop)

    result = service.resume(
        loop_id=loop.loop_id,
        actor="bob",
        approved_by="cara",
        signature="sig-123",
    )

    assert result.phase is LoopPhase.RESUMED
    assert result.pause_attempts == 1
    assert result.paused_at is None
    assert result.resumed_at == T0
    assert len(audit.events) == 1
    ev = audit.events[0]
    assert ev["action"] == LOOP_RESUMED
    assert ev["actor"] == "bob"
    assert ev["payload"]["approved_by"] == "cara"
    assert ev["payload"]["phase"] == "RESUMED"
    assert ev["payload"]["pause_attempts"] == 1
    # t0 - t0 = 0 wall credit
    assert ev["payload"]["wall_credit_seconds"] == 0
    # Approval passed through loop_id/actor/approved_by/signature.
    assert approval.calls[0]["approved_by"] == "cara"
    assert approval.calls[0]["signature"] == "sig-123"


def test_resume_rejected_when_stopped() -> None:
    repo, _audit, _approval, service = _harness()
    loop = _loop(phase=LoopPhase.EMERGENCY_STOPPED)
    repo.save(loop)

    with pytest.raises(Exception) as exc_info:
        service.resume(loop_id=loop.loop_id, actor="bob", approved_by="cara", signature="s")
    assert "cannot resume" in str(exc_info.value)


def test_pause_budget_exceeded_stops() -> None:
    # max_pauses=1: a state already at pause_attempts=1 cannot resume.
    policy = LoopTerminationPolicy(
        max_steps=50,
        max_wall_clock_seconds=1800,
        max_total_tokens=200_000,
        no_signal_streak_to_converge=5,
        policy_rejected_streak_to_stop=3,
        require_min_confirmed=0,
        max_pauses=1,
    )
    repo, _audit, _approval, service = _harness(policy=policy)
    loop = _loop(phase=LoopPhase.PAUSED, pause_attempts=1, paused_at=T0)  # type: ignore[arg-type]
    repo.save(loop)

    with pytest.raises(PauseBudgetExceeded):
        service.resume(
            loop_id=loop.loop_id,
            actor="bob",
            approved_by="cara",
            signature="sig-123",
        )
