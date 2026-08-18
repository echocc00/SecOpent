# src/secopent/application/reasoning_loop/feedback.py
"""LoopFeedback — deterministic state delta after a step (spec §8)."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime

from ...domain.reasoning_loop.models import (
    LoopBudget,
    LoopState,
    LoopStep,
)


class LoopFeedback:
    """Produces a new LoopState after a step is recorded.

    Pure: same input ⇒ same output. No side effects.
    """

    def apply(
        self,
        *,
        current: LoopState,
        step: LoopStep,
        policy_decision_passed: bool,
        signal_count: int,
        now: datetime,
    ) -> LoopState:
        # 1. Decrement budget by 1 step + tokens consumed.
        new_budget: LoopBudget = current.budget.consume(
            steps=1,
            tokens=step.propose_tokens_used,
        )

        # 2. Move matched catalog classes from remaining → executed.
        new_remaining = current.catalog_required_remaining - step.catalog_class_matched
        new_executed = current.catalog_required_executed | step.catalog_class_matched

        # 3. Streak counters.
        new_no_signal = 0 if signal_count > 0 else current.consecutive_no_signal + 1
        new_policy_rej = 0 if policy_decision_passed else current.consecutive_policy_rejected + 1

        return replace(
            current,
            budget=new_budget,
            catalog_required_remaining=new_remaining,
            catalog_required_executed=new_executed,
            consecutive_no_signal=new_no_signal,
            consecutive_policy_rejected=new_policy_rej,
            last_step_at=now,
        )
