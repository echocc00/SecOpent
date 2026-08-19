"""BudgetGateImpl — per-step token cap + hard cumulative budget limits
(spec §10, v0.7.3 Task 2).

The gate guards each propose step against two independent classes of risk:
1. **Runaway single step** — one proposal asking for more than `STEP_TOKEN_LIMIT`
   tokens in a single step is rejected outright (``BUDGET_STEP_TOKEN_LIMIT``).
2. **Hard cumulative limits** — if consuming this step's token allocation would
   push any of the three hard limits (steps > 50 / total tokens > 200K /
   wall > 1800s) past its cap, the loop is spent and the step is denied
   (``BUDGET_EXHAUSTED``). This is terminal: the orchestrator MUST transition
   to ``BUDGET_EXHAUSTED`` and stop issuing work.

The gate is pure and immutable w.r.t. the loop budget: it reads the current
``LoopBudget`` through an injected ``budget_now`` callable and computes the
post-step projection via ``LoopBudget.consume`` (which returns a NEW instance
and never mutates). This keeps the gate trivially testable with a controllable
budget state and lets the orchestrator supply the authoritative budget source.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ...domain.reasoning_loop.models import GateVerdict, LoopBudget

# v0.7.3: hard cap on the token allocation of a SINGLE propose step.
STEP_TOKEN_LIMIT = 8000


class BudgetGateImpl:
    """Rejects oversized single steps and spends that would exhaust the budget.

    Unlike the Schema/Policy/Permit gates, ``check`` does not take a
    ``LoopContext`` — it only needs the proposed action and its token
    allocation, plus the current budget state injected at construction.
    """

    def __init__(self, *, budget_now: Callable[[], LoopBudget]) -> None:
        self._budget_now = budget_now

    def check(self, action: Any, proposed_tokens: int) -> GateVerdict:
        budget = self._budget_now()

        if proposed_tokens > STEP_TOKEN_LIMIT:
            return GateVerdict(
                passed=False,
                reason=(
                    f"proposed step allocates {proposed_tokens} tokens, "
                    f"over the {STEP_TOKEN_LIMIT} per-step limit"
                ),
                deny_code="BUDGET_STEP_TOKEN_LIMIT",
            )

        # Project the cumulative budget AFTER this step: if any hard limit is
        # (or would be) hit, the loop is exhausted and MUST stop. Because
        # ``consume`` returns a new instance, we do not mutate the live budget.
        post = budget.consume(tokens=proposed_tokens)
        if post.exhausted():
            return GateVerdict(
                passed=False,
                reason=(
                    f"budget exhausted: steps={post.steps_used}/{post.max_steps}, "
                    f"tokens={post.tokens_used}/{post.max_total_tokens}, "
                    f"wall={post.wall_seconds_used}s/{post.max_wall_seconds}s"
                ),
                deny_code="BUDGET_EXHAUSTED",
            )

        return GateVerdict(passed=True, reason="budget_ok")