"""Tests for the deterministic ReasoningLoop termination evaluator (spec §5)."""
from __future__ import annotations

from datetime import UTC, datetime

from secopent.domain.reasoning_loop.models import (
    LoopBudget,
    LoopId,
    LoopPhase,
    LoopState,
    LoopTerminationPolicy,
)
from secopent.domain.reasoning_loop.policies import evaluate_termination

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _state(**overrides) -> LoopState:
    base = dict(
        loop_id=LoopId(value="abcd1234"),
        assessment_id="asmt-1",
        phase=LoopPhase.RUNNING,
        policy_snapshot="sha256:" + "0" * 64,
        budget=LoopBudget.default(),
        context_hash="0" * 64,
        catalog_required_remaining=frozenset(),
        catalog_required_executed=frozenset({"web:xss", "web:sqli"}),
        consecutive_no_signal=0,
        consecutive_policy_rejected=0,
        started_at=_T0,
        last_step_at=_T0,
    )
    base.update(overrides)
    return LoopState(**base)


def test_evaluate_returns_RUNNING_when_no_trigger() -> None:
    s = _state()
    assert evaluate_termination(s, LoopTerminationPolicy.default()) is LoopPhase.RUNNING


def test_evaluate_returns_COMPLETED_when_all_termination_met_but_floor_red() -> None:
    """Spec §6.1: catalog floor is NOT a loop terminator. A loop may COMPLETE
    (e.g. converged) even when the floor is still red — the floor is the
    Assessment's CoverageService gate, not the loop's."""
    # converge (no-signal streak) with floor red → CONVERGED (a terminal state)
    s = _state(
        consecutive_no_signal=5,
        catalog_required_remaining=frozenset({"web:xss"}),  # floor NOT green
    )
    assert evaluate_termination(s, LoopTerminationPolicy.default()) is LoopPhase.CONVERGED


def test_evaluate_NO_longer_uses_floor_to_gate_COMPLETED() -> None:
    """Spec §6.1: floor-green must NOT alone force COMPLETED. With no other
    trigger present, a floor-green loop with steps remaining is RUNNING."""
    s = _state(catalog_required_remaining=frozenset(), last_step_at=_T0, consecutive_no_signal=0)
    assert evaluate_termination(s, LoopTerminationPolicy.default()) is LoopPhase.RUNNING


def test_evaluate_returns_BUDGET_EXHAUSTED_when_steps_hit_max() -> None:
    budget = LoopBudget.default().consume(steps=50)
    s = _state(budget=budget, catalog_required_remaining=frozenset({"web:xss"}))  # floor NOT green
    assert evaluate_termination(s, LoopTerminationPolicy.default()) is LoopPhase.BUDGET_EXHAUSTED


def test_evaluate_returns_BUDGET_EXHAUSTED_when_tokens_hit_max() -> None:
    budget = LoopBudget.default().consume(tokens=200_000)
    s = _state(budget=budget, catalog_required_remaining=frozenset({"web:xss"}))
    assert evaluate_termination(s, LoopTerminationPolicy.default()) is LoopPhase.BUDGET_EXHAUSTED


def test_evaluate_returns_BUDGET_EXHAUSTED_when_wall_clock_hit_max() -> None:
    budget = LoopBudget.default().consume(wall_seconds=1800)
    s = _state(budget=budget, catalog_required_remaining=frozenset({"web:xss"}))
    assert evaluate_termination(s, LoopTerminationPolicy.default()) is LoopPhase.BUDGET_EXHAUSTED


def test_evaluate_returns_CONVERGED_on_no_signal_streak() -> None:
    s = _state(
        consecutive_no_signal=5,
        catalog_required_remaining=frozenset({"web:xss"}),  # floor NOT green
    )
    assert evaluate_termination(s, LoopTerminationPolicy.default()) is LoopPhase.CONVERGED


def test_evaluate_returns_POLICY_BLOCKED_on_gate_streak() -> None:
    s = _state(
        consecutive_policy_rejected=3,
        catalog_required_remaining=frozenset({"web:xss"}),
    )
    assert evaluate_termination(s, LoopTerminationPolicy.default()) is LoopPhase.POLICY_BLOCKED


def test_evaluate_EMERGENCY_STOPPED_wins_over_everything_else() -> None:
    s = _state(phase=LoopPhase.EMERGENCY_STOPPED)
    assert evaluate_termination(s, LoopTerminationPolicy.default()) is LoopPhase.EMERGENCY_STOPPED


def test_evaluate_PAUSED_respected_and_does_not_terminate() -> None:
    """Spec §6.3 (v0.7.0 skeleton: state exists; full API in v0.7.7). A PAUSED
    loop stays PAUSED — the orchestrator must not advance/terminate it."""
    s = _state(phase=LoopPhase.PAUSED, consecutive_no_signal=5)
    assert evaluate_termination(s, LoopTerminationPolicy.default()) is LoopPhase.PAUSED


def test_evaluate_priority_budget_over_converged_when_floor_not_green() -> None:
    """Spec §5: budget exhaustion is HARD — wins over heuristic convergence."""
    budget = LoopBudget.default().consume(steps=50)
    s = _state(
        budget=budget,
        consecutive_no_signal=10,  # would otherwise CONVERGE
        catalog_required_remaining=frozenset({"web:xss"}),
    )
    assert evaluate_termination(s, LoopTerminationPolicy.default()) is LoopPhase.BUDGET_EXHAUSTED


def test_evaluate_lowest_priority_is_RUNNING() -> None:
    """Spec §6.1: with no trigger, loop keeps running regardless of floor state."""
    s = _state(catalog_required_remaining=frozenset({"web:xss"}))  # floor red
    assert evaluate_termination(s, LoopTerminationPolicy.default()) is LoopPhase.RUNNING
