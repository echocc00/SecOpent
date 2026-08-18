"""Deterministic termination evaluator for ReasoningLoop (spec §5).

This module has NO framework dependencies — pure functions over frozen
dataclasses. Same input ⇒ same output, always. The orchestrator must call
``evaluate_termination(state, policy)`` after every step; the returned phase
is the loop's next phase (and, when terminal, the loop stops issuing work).
"""
from __future__ import annotations

from .models import LoopPhase, LoopState, LoopTerminationPolicy


# Priority order — first match wins. Higher-priority terminal states must
# appear before softer ones so budget exhaustion always trumps CONVERGED.
def evaluate_termination(
    state: LoopState, policy: LoopTerminationPolicy
) -> LoopPhase:
    """Return the loop's next phase given current state.

    Order of checks (spec §5 + §6.1 + §6.3):
    1. EMERGENCY_STOPPED wins everything.
    2. PAUSED short-circuits: a paused loop stays PAUSED (orchestrator must
       not advance/terminate it). RESUMED falls through to §6.3 semantics.
    3. Budget exhausted ⇒ BUDGET_EXHAUSTED (hard stop; catalog floor may be red).
    4. Policy rejected streak reached ⇒ POLICY_BLOCKED.
    5. No-signal streak reached ⇒ CONVERGED.
    6. Otherwise ⇒ RUNNING (continue).

    NOTE: catalog floor is NOT a termination condition (spec §6.1). It is the
    Assessment's CoverageService gate, surfaced to the LLM via
    LoopContext.catalog_* as informational input only. There is therefore no
    COMPLETED-by-floor branch.
    """
    if state.phase is LoopPhase.EMERGENCY_STOPPED:
        return LoopPhase.EMERGENCY_STOPPED

    if state.phase is LoopPhase.PAUSED:
        return LoopPhase.PAUSED

    if state.budget.exhausted():
        return LoopPhase.BUDGET_EXHAUSTED

    if (
        state.consecutive_policy_rejected
        >= policy.policy_rejected_streak_to_stop
    ):
        return LoopPhase.POLICY_BLOCKED

    if (
        state.consecutive_no_signal
        >= policy.no_signal_streak_to_converge
    ):
        return LoopPhase.CONVERGED

    return LoopPhase.RUNNING
