# tests/application/reasoning_loop/test_feedback.py
"""LoopFeedback — produce next LoopState after a step (spec §8)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from secopent.application.reasoning_loop.feedback import LoopFeedback
from secopent.domain.reasoning_loop.models import (
    LoopActionType,
    LoopBudget,
    LoopId,
    LoopPhase,
    LoopState,
    LoopStep,
    PolicyDecision,
    ProposeAction,
)

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _state(**overrides) -> LoopState:
    base = dict(
        loop_id=LoopId(value="abcd1234"),
        assessment_id="asmt-1",
        phase=LoopPhase.RUNNING,
        policy_snapshot="sha256:" + "0" * 64,
        budget=LoopBudget.default(),
        context_hash="0" * 64,
        catalog_required_remaining=frozenset({"web:sqli"}),
        catalog_required_executed=frozenset(),
        consecutive_no_signal=0,
        consecutive_policy_rejected=0,
        started_at=_T0,
        last_step_at=None,
    )
    base.update(overrides)
    return LoopState(**base)


def _step(
    *,
    signals=("sig-1",),
    matched=frozenset({"web:sqli"}),
    tokens=100,
) -> LoopStep:
    pa = ProposeAction(
        action_type=LoopActionType.RUN_TOOL,
        payload={"tool_id": "nuclei", "parameters": {}},
        rationale="x" * 80,
        confidence=0.5,
    )
    return LoopStep(
        step_id="step-1", loop_id=LoopId(value="abcd1234"), step_number=1,
        timestamp=_T0, context_hash_before="0" * 64,
        proposed_action=pa, propose_tokens_used=tokens, propose_latency_ms=100,
        propose_rationale=pa.rationale,
        schema_check_passed=True,
        policy_decision=PolicyDecision(verdict="allow", reason="ok"),
        permit_id="permit-1", tool_or_case_id="nuclei",
        execution_result_digest="sha256:" + "a" * 64,
        evidence_refs=(), observation_signals=signals,
        catalog_class_matched=matched, oracle_progressed=False,
        correlation_id="corr-1",
    )


def test_feedback_decrements_budget_by_step_cost() -> None:
    fb = LoopFeedback()
    next_state = fb.apply(
        current=_state(),
        step=_step(tokens=500),
        policy_decision_passed=True,
        signal_count=1,
        now=_T0,
    )
    assert next_state.budget.snapshot().steps_remaining == 49
    assert next_state.budget.snapshot().tokens_remaining == 199_500


def test_feedback_adds_catalog_classes_matched_to_executed() -> None:
    fb = LoopFeedback()
    next_state = fb.apply(
        current=_state(catalog_required_remaining=frozenset({"web:sqli"})),
        step=_step(matched=frozenset({"web:sqli"})),
        policy_decision_passed=True,
        signal_count=1,
        now=_T0,
    )
    assert next_state.catalog_required_remaining == frozenset()
    assert next_state.catalog_required_executed == frozenset({"web:sqli"})


def test_feedback_increments_consecutive_no_signal_on_zero_signals() -> None:
    fb = LoopFeedback()
    next_state = fb.apply(
        current=_state(consecutive_no_signal=2),
        step=_step(signals=()),
        policy_decision_passed=True,
        signal_count=0,
        now=_T0,
    )
    assert next_state.consecutive_no_signal == 3


def test_feedback_resets_consecutive_no_signal_when_signals_present() -> None:
    fb = LoopFeedback()
    next_state = fb.apply(
        current=_state(consecutive_no_signal=4),
        step=_step(signals=("new",)),
        policy_decision_passed=True,
        signal_count=1,
        now=_T0,
    )
    assert next_state.consecutive_no_signal == 0


def test_feedback_increments_consecutive_policy_rejected_on_deny() -> None:
    fb = LoopFeedback()
    next_state = fb.apply(
        current=_state(consecutive_policy_rejected=1),
        step=_step(),
        policy_decision_passed=False,
        signal_count=0,
        now=_T0,
    )
    assert next_state.consecutive_policy_rejected == 2


def test_feedback_resets_consecutive_policy_rejected_on_pass() -> None:
    fb = LoopFeedback()
    next_state = fb.apply(
        current=_state(consecutive_policy_rejected=2),
        step=_step(),
        policy_decision_passed=True,
        signal_count=1,
        now=_T0,
    )
    assert next_state.consecutive_policy_rejected == 0


def test_feedback_updates_last_step_at() -> None:
    fb = LoopFeedback()
    next_state = fb.apply(
        current=_state(last_step_at=None),
        step=_step(),
        policy_decision_passed=True,
        signal_count=1,
        now=_T0 + timedelta(seconds=10),
    )
    assert next_state.last_step_at == _T0 + timedelta(seconds=10)
