# tests/application/test_wall_clock_paused.py
"""Wall-clock credit: pause-period seconds must NOT count toward the loop
budget (spec §6.3, v0.7.7 Task 4).

Covered via PauseControlService up at the application boundary, so the whole
resume path is exercised: pause at t1, resume at t2, and verify the resumed
state's ``budget.wall_seconds_used`` already reflects the credit subtraction.
``credit_budget`` is also unit-tested directly for the edge cases.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from secopent.application.ports.loop_approval import validate_loop_approval_params
from secopent.application.reasoning_loop.pause_control import (
    PauseControlService,
    credit_budget,
)
from secopent.domain.reasoning_loop.models import (
    LoopBudget,
    LoopId,
    LoopPhase,
    LoopState,
)

T0 = datetime(2026, 8, 19, 12, 0, 0, tzinfo=UTC)


class _Repo:
    def __init__(self) -> None:
        self._state: LoopState | None = None
        self.save_count = 0

    def get(self, loop_id: object) -> LoopState | None:
        return self._state

    def save(self, state: LoopState) -> None:
        self.save_count += 1
        self._state = state


class _Audit:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

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
        self.events.append(payload)
        return None


class _Approval:
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
        validate_loop_approval_params(
            actor_role=actor_role, approved_by=approved_by, signature=signature
        )


def _loop(budget: LoopBudget) -> LoopState:
    return LoopState(
        loop_id=LoopId.new(),
        assessment_id="assessment-1",
        phase=LoopPhase.PAUSED,
        policy_snapshot="policy-snap",
        budget=budget,
        context_hash="ctx-hash",
        catalog_required_remaining=frozenset(),
        catalog_required_executed=frozenset(),
        consecutive_no_signal=0,
        consecutive_policy_rejected=0,
        started_at=T0,
        last_step_at=T0,
        pause_attempts=0,
        paused_at=T0,
    )


def _service(now_fn, repo: _Repo, budget: LoopBudget):
    audit = _Audit()
    svc = PauseControlService(
        state_repo=repo,
        audit=audit,
        approval=_Approval(),
        now_fn=now_fn,
    )
    return svc, audit


def _resume_after(seconds: int) -> tuple[LoopState, int, int]:
    """Run pause at t0 then resume at t0+seconds; return the resumed state,
    the wall_seconds_used before credit, and the wall_seconds_used after."""
    budget = LoopBudget.default().consume(wall_seconds=400)
    repo = _Repo()
    repo._state = _loop(budget)
    before = budget.wall_seconds_used

    clock = {"t": T0}

    def now_fn() -> datetime:
        return clock["t"]

    svc, _audit = _service(now_fn, repo, budget)
    svc.pause(loop_id=repo._state.loop_id, actor="alice", reason="review")
    clock["t"] = T0 + timedelta(seconds=seconds)
    resumed = svc.resume(
        loop_id=repo._state.loop_id,
        actor="bob",
        approved_by="cara",
        signature="sig",
    )
    return resumed, before, resumed.budget.wall_seconds_used


def test_pause_credit_subtracted_on_resume() -> None:
    # Pause spans 600s of wall clock; those seconds must NOT count toward budget.
    resumed, before, after = _resume_after(600)
    assert before == 400
    # 400 - 600 floors at 0.
    assert after == 0


def test_pause_credit_subtracted_partial() -> None:
    # 400 consumed, pause of 250s -> 400 - 250 = 150.
    resumed, before, after = _resume_after(250)
    assert before == 400
    assert after == 150


def test_no_pause_no_credit() -> None:
    """credit_budget with 0 credit is identity on wall_seconds_used."""
    budget = LoopBudget.default().consume(wall_seconds=100)
    credited = credit_budget(budget, wall_credit_seconds=0)
    assert credited.wall_seconds_used == 100
    # All other fields copied unchanged.
    assert credited.max_steps == budget.max_steps
    assert credited.steps_used == budget.steps_used
    assert credited.tokens_used == budget.tokens_used


def test_credit_never_goes_negative() -> None:
    budget = LoopBudget.default().consume(wall_seconds=100)
    credited = credit_budget(budget, wall_credit_seconds=10_000)
    assert credited.wall_seconds_used == 0
    # Assert credit_budget is pure: original untouched.
    assert budget.wall_seconds_used == 100
