"""secopent loop CLI - human entry points into the ReasoningLoop (v0.7.8 M5).

Small diagnostic commands (create / status / stop / history) that build a
short-lived in-memory ReasoningLoop runtime and print results with exit codes
0 (success) / 1 (error). The CLI is a thin dispatcher - it owns no business
logic and delegates to the domain models + loop repos exactly like the MCP
handlers.

    secopent loop create --assessment-id A [--max-steps N]
                         [--max-wall-seconds S] [--max-total-tokens T] [--actor op]
    secopent loop status --loop-id X
    secopent loop history --loop-id X
    secopent loop stop --loop-id X [--actor op]

Persistence note: the loop state/step repos here are process-local in-memory
singletons (mirroring the API server's shared ``app.state.loop_state_repo`` /
``loop_step_repo``), so consecutive commands in ONE process see the same loops.
State does NOT survive separate CLI process invocations - this is a diagnostic
surface, not the DB-backed loop store (the SQL repos + persistence live behind
the MCP/API surface; see ``infrastructure/reasoning_loop/``).
"""
from __future__ import annotations

import contextlib
import sys
from collections.abc import Iterator

from ...application.ports.loop_state import LoopStateRepository
from ...application.ports.loop_step import LoopStepRepository
from ...application.reasoning_loop.in_memory_state import (
    InMemoryLoopStateRepository,
    InMemoryLoopStepRepository,
)
from ...domain.reasoning_loop.models import (
    LoopBudget,
    LoopId,
    LoopPhase,
    LoopPlan,
    LoopState,
    LoopTerminationPolicy,
)

# Process-local loop runtime (module singleton): a short-lived in-memory
# state + step pair shared across commands in the same process.
_STATE_REPO = InMemoryLoopStateRepository()
_STEP_REPO = InMemoryLoopStepRepository()


@contextlib.contextmanager
def _loop_runtime() -> Iterator[tuple[LoopStateRepository, LoopStepRepository]]:
    """Yield the (state, step) loop repos for this CLI session.

    The repos are process-local in-memory singletons, so a sequence of loop
    commands in one process shares the same loops (create -> status/history/stop
    round-trips work). Mirror of grants.py``_grant_service`` shape, but over the
    in-memory stores rather than a SQL session (no DB dependency for diagnostics).
    """
    yield _STATE_REPO, _STEP_REPO


def _loop_id(value: str) -> LoopId:
    """Validate a --loop-id value, raising ValueError on malformed ids."""
    return LoopId(value)


def cmd_loop_create(
    assessment_id: str,
    *,
    max_steps: int | None,
    max_wall_seconds: int | None,
    max_total_tokens: int | None,
    actor: str,
) -> int:
    """Create an INITIALIZING ReasoningLoop and print its loop_id (exit 0/1)."""
    from ...domain.common.canonical import utc_now

    try:
        base = LoopBudget.default()
        budget = LoopBudget(
            max_steps=max_steps if max_steps is not None else base.max_steps,
            max_total_tokens=(
                max_total_tokens if max_total_tokens is not None
                else base.max_total_tokens
            ),
            max_wall_seconds=(
                max_wall_seconds if max_wall_seconds is not None
                else base.max_wall_seconds
            ),
        )
        loop_id = LoopId.new()
        now = utc_now()
        plan = LoopPlan(
            plan_id=f"plan-{loop_id.value}",
            loop_id=loop_id,
            assessment_id=assessment_id,
            termination_policy=LoopTerminationPolicy.default(),
            policy_snapshot="cli:loop:default",
            created_at=now,
        )
        state = LoopState(
            loop_id=plan.loop_id,
            assessment_id=plan.assessment_id,
            phase=LoopPhase.INITIALIZING,
            policy_snapshot=plan.policy_snapshot,
            budget=budget,
            context_hash="0" * 64,
            catalog_required_remaining=frozenset(),
            catalog_required_executed=frozenset(),
            consecutive_no_signal=0,
            consecutive_policy_rejected=0,
            started_at=now,
            last_step_at=None,
        )
        with _loop_runtime() as (state_repo, _step_repo):
            state_repo.save(state)
    except Exception as exc:  # noqa: BLE001 - CLI surfaces the domain error
        print(f"error: loop create failed: {exc}", file=sys.stderr)
        return 1
    print(f"created loop {loop_id.value} for assessment {assessment_id}")
    print(f"  phase: {state.phase.value}; max_steps: {budget.max_steps}; actor: {actor}")
    return 0


def cmd_loop_status(loop_id: str) -> int:
    """Print the loop's phase + step count (exit 0/1)."""
    try:
        lid = _loop_id(loop_id)
        with _loop_runtime() as (state_repo, step_repo):
            state = state_repo.get(lid)
            if state is None:
                print(f"error: loop {loop_id!r} not found", file=sys.stderr)
                return 1
            steps = step_repo.list_for_loop(lid)
            budget = state.budget.snapshot()
    except Exception as exc:  # noqa: BLE001 - CLI surfaces the domain error
        print(f"error: loop status failed: {exc}", file=sys.stderr)
        return 1
    print(f"loop {state.loop_id.value} phase={state.phase.value}")
    print(
        f"  steps: {len(steps)}; budget_remaining: "
        f"steps={budget.steps_remaining}, tokens={budget.tokens_remaining}, "
        f"wall={budget.wall_seconds_remaining}s"
    )
    return 0


def cmd_loop_history(loop_id: str) -> int:
    """Print every recorded step for the loop (exit 0/1)."""
    try:
        lid = _loop_id(loop_id)
        with _loop_runtime() as (state_repo, step_repo):
            state = state_repo.get(lid)
            if state is None:
                print(f"error: loop {loop_id!r} not found", file=sys.stderr)
                return 1
            steps = step_repo.list_for_loop(lid)
    except Exception as exc:  # noqa: BLE001 - CLI surfaces the domain error
        print(f"error: loop history failed: {exc}", file=sys.stderr)
        return 1
    print(f"loop {state.loop_id.value} history ({len(steps)} steps):")
    for step in steps:
        print(
            f"  #{step.step_number}\t{step.proposed_action.action_type.value}\t"
            f"tool={step.tool_or_case_id}\toracle_progressed={step.oracle_progressed}"
        )
    return 0


def cmd_loop_stop(loop_id: str, actor: str) -> int:
    """Transition the loop to the terminal EMERGENCY_STOPPED phase (exit 0/1)."""
    from dataclasses import replace

    from ...domain.common.canonical import utc_now

    try:
        lid = _loop_id(loop_id)
        with _loop_runtime() as (state_repo, _step_repo):
            state = state_repo.get(lid)
            if state is None:
                print(f"error: loop {loop_id!r} not found", file=sys.stderr)
                return 1
            if state.phase is not LoopPhase.EMERGENCY_STOPPED:
                stopped = replace(
                    state,
                    phase=LoopPhase.EMERGENCY_STOPPED,
                    last_step_at=utc_now(),
                )
                state_repo.save(stopped)
                phase = stopped.phase
            else:
                phase = state.phase
    except Exception as exc:  # noqa: BLE001 - CLI surfaces the domain error
        print(f"error: loop stop failed: {exc}", file=sys.stderr)
        return 1
    print(f"stopped loop {loop_id} (phase={phase.value}; actor={actor})")
    return 0
