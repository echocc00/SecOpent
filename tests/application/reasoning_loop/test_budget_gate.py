# tests/application/reasoning_loop/test_budget_gate.py
"""BudgetGateImpl — per-step token cap + hard cumulative budget limits
(spec §10, v0.7.3 Task 2).

Deny codes:
- BUDGET_STEP_TOKEN_LIMIT  single proposal exceeds the 8K per-step token cap
- BUDGET_EXHAUSTED          proposed step would push any hard limit
  (steps > 50 / total tokens > 200K / wall > 1800s)
"""
from __future__ import annotations

from secopent.application.reasoning_loop.budget_gate import BudgetGateImpl
from secopent.domain.reasoning_loop.models import LoopBudget

_STEP_TOKEN_LIMIT = 8000


def _gate(budget: LoopBudget) -> BudgetGateImpl:
    # Inject a closed-over budget so the test holds a controllable handle to
    # mutate what `budget_now()` returns for the next `check` call.
    return BudgetGateImpl(budget_now=lambda: budget)


def test_accepts_action_under_single_step_token_cap() -> None:
    gate = _gate(LoopBudget.default())
    verdict = gate.check(action={"action_type": "abort_step"}, proposed_tokens=100)
    assert verdict.passed is True
    assert verdict.deny_code is None


def test_rejects_single_step_tokens_over_8k() -> None:
    gate = _gate(LoopBudget.default())
    verdict = gate.check(action={"action_type": "run_tool"}, proposed_tokens=_STEP_TOKEN_LIMIT + 1)
    assert verdict.passed is False
    assert verdict.deny_code == "BUDGET_STEP_TOKEN_LIMIT"


def test_accepts_8k_step_exactly() -> None:
    gate = _gate(LoopBudget.default())
    assert gate.check(action={}, proposed_tokens=_STEP_TOKEN_LIMIT).passed is True


def test_denies_when_steps_already_at_limit() -> None:
    budget = LoopBudget.default().consume(steps=50)
    gate = _gate(budget)
    verdict = gate.check(action={}, proposed_tokens=100)
    assert verdict.passed is False
    assert verdict.deny_code == "BUDGET_EXHAUSTED"


def test_denies_when_total_tokens_over_200k() -> None:
    budget = LoopBudget.default().consume(tokens=200_000)
    gate = _gate(budget)
    verdict = gate.check(action={}, proposed_tokens=100)
    assert verdict.passed is False
    assert verdict.deny_code == "BUDGET_EXHAUSTED"


def test_denies_when_wall_seconds_exceeded() -> None:
    budget = LoopBudget.default().consume(wall_seconds=1800)
    gate = _gate(budget)
    verdict = gate.check(action={}, proposed_tokens=100)
    assert verdict.passed is False
    assert verdict.deny_code == "BUDGET_EXHAUSTED"


def test_denies_when_proposal_pushes_total_over_200k() -> None:
    # Not yet exhausted, but consuming this proposal would cross the 200K cap.
    budget = LoopBudget.default().consume(tokens=199_900)
    gate = _gate(budget)
    verdict = gate.check(action={}, proposed_tokens=200)
    assert verdict.passed is False
    assert verdict.deny_code == "BUDGET_EXHAUSTED"


def test_accepts_step_within_remaining_token_headroom() -> None:
    budget = LoopBudget.default().consume(tokens=199_900)
    gate = _gate(budget)
    # 200_000 - 199_900 = 100 headroom; a 90-token proposal stays under.
    assert gate.check(action={}, proposed_tokens=90).passed is True


def test_budget_not_mutated_by_check() -> None:
    """check must be pure w.r.t. the loop budget (consume returns a new
    instance; the injected budget must be left untouched)."""
    budget = LoopBudget.default()
    gate = _gate(budget)
    gate.check(action={}, proposed_tokens=100)
    gate.check(action={}, proposed_tokens=100)
    assert budget.steps_used == 0
    assert budget.tokens_used == 0
    assert budget.wall_seconds_used == 0