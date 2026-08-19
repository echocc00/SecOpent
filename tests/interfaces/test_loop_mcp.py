# tests/interfaces/test_loop_mcp.py
"""Direct handler tests for the ReasingLoop MCP surface (v0.7.8 Task 4).

Covers the four new loop tools by calling the handlers DIRECTLY with a fake
``McpRuntime`` (no FastMCP server), matching the existing MCP handler tests:

- ``loop_status``  (agent + human, read-only) -> phase/step_count/
  budget_remaining/context_hash; unknown loop -> structured NOT_FOUND via
  ``_guard``.
- ``loop_history`` (agent + human, read-only) -> steps list with
  step_id/step_number/action_type/tool_or_case_id/oracle_progressed.
- ``loop_create``  (human-only via grant_id) -> creates a loop; no grant ->
  structured HUMAN_REQUIRED.
- ``loop_stop``    (human-only via grant_id) -> EMERGENCY_STOPPED; no grant ->
  structured HUMAN_REQUIRED.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from secopent.application.reasoning_loop.in_memory_state import (
    InMemoryLoopStateRepository,
    InMemoryLoopStepRepository,
)
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
from secopent.interfaces.mcp.handlers import (
    McpRuntime,
    handler_loop_create,
    handler_loop_history,
    handler_loop_status,
    handler_loop_stop,
)


class _FakeAudit:
    """Minimal AuditRecorder stand-in; the loop handlers only call record()."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def record(self, **kwargs: Any) -> object:
        self.events.append(kwargs)
        return kwargs


def _runtime(
    *, state_repo: InMemoryLoopStateRepository,
    step_repo: InMemoryLoopStepRepository,
) -> McpRuntime:
    return McpRuntime(
        db=cast(Any, object()),  # loop handlers never touch runtime.db
        audit_chain=_FakeAudit(),  # type: ignore[arg-type]
        loop_state_repo=state_repo,
        loop_step_repo=step_repo,
    )


def _loop(lid: LoopId, *, phase: LoopPhase = LoopPhase.RUNNING) -> LoopState:
    return LoopState(
        loop_id=lid,
        assessment_id="assessment-1",
        phase=phase,
        policy_snapshot="policy-snap",
        budget=LoopBudget.default(),
        context_hash="cafecafe" * 8,
        catalog_required_remaining=frozenset(),
        catalog_required_executed=frozenset(),
        consecutive_no_signal=0,
        consecutive_policy_rejected=0,
        started_at=datetime(2026, 8, 19, 12, 0, 0, tzinfo=UTC),
        last_step_at=None,
    )


def _step(state: LoopState, *, number: int = 1) -> LoopStep:
    return LoopStep(
        step_id=f"step-{number}",
        loop_id=state.loop_id,
        step_number=number,
        timestamp=datetime(2026, 8, 19, 12, 0, 0, tzinfo=UTC),
        context_hash_before=state.context_hash,
        proposed_action=ProposeAction(
            action_type=LoopActionType.RUN_CASE,
            payload={"case_id": "case-x", "parameters": {}},
            rationale=("rationale " * 10).strip(),
            confidence=0.9,
        ),
        propose_tokens_used=100,
        propose_latency_ms=50,
        propose_rationale="ok",
        schema_check_passed=True,
        policy_decision=PolicyDecision(verdict="allow", reason="ok"),
        permit_id="permit-1",
        tool_or_case_id="case-x",
        execution_result_digest="sha256:abc",
        evidence_refs=(),
        observation_signals=(),
        catalog_class_matched=frozenset(),
        oracle_progressed=True,
        correlation_id="corr-1",
    )


def test_loop_status_returns_phase_and_remains() -> None:
    state_repo = InMemoryLoopStateRepository()
    step_repo = InMemoryLoopStepRepository()
    lid = LoopId.new()
    state = _loop(lid)
    state_repo.save(state)
    step_repo.add(_step(state, number=1))
    step_repo.add(_step(state, number=2))

    result = handler_loop_status(
        _runtime(state_repo=state_repo, step_repo=step_repo), loop_id=lid.value
    )

    assert result["status"] == "success"
    assert result["loop_id"] == lid.value
    assert result["phase"] == LoopPhase.RUNNING.value
    assert result["step_count"] == 2
    assert result["context_hash"] == state.context_hash
    budget = result["budget_remaining"]
    assert isinstance(budget, dict)
    assert budget["steps"] == LoopBudget.default().max_steps


def test_loop_status_not_found_returns_structured_NOT_FOUND() -> None:
    result = handler_loop_status(
        _runtime(
            state_repo=InMemoryLoopStateRepository(),
            step_repo=InMemoryLoopStepRepository(),
        ),
        loop_id=LoopId.new().value,
    )
    assert result["status"] == "error"
    assert result["code"] == "NOT_FOUND"


def test_loop_history_returns_steps() -> None:
    state_repo = InMemoryLoopStateRepository()
    step_repo = InMemoryLoopStepRepository()
    state = _loop(LoopId.new())
    state_repo.save(state)
    step_repo.add(_step(state, number=1))

    result = handler_loop_history(
        _runtime(state_repo=state_repo, step_repo=step_repo),
        loop_id=state.loop_id.value,
    )

    assert result["status"] == "success"
    steps = result["steps"]
    assert isinstance(steps, list)
    assert len(steps) == 1
    step = steps[0]
    assert step["step_id"] == "step-1"
    assert step["step_number"] == 1
    assert step["action_type"] == LoopActionType.RUN_CASE.value
    assert step["tool_or_case_id"] == "case-x"
    assert step["oracle_progressed"] is True


def test_loop_history_not_found_returns_NOT_FOUND() -> None:
    result = handler_loop_history(
        _runtime(
            state_repo=InMemoryLoopStateRepository(),
            step_repo=InMemoryLoopStepRepository(),
        ),
        loop_id=LoopId.new().value,
    )
    assert result["status"] == "error"
    assert result["code"] == "NOT_FOUND"


def test_loop_create_with_grant_creates_loop() -> None:
    state_repo = InMemoryLoopStateRepository()
    step_repo = InMemoryLoopStepRepository()

    result = handler_loop_create(
        _runtime(state_repo=state_repo, step_repo=step_repo),
        assessment_id="assessment-1",
        grant_id="grant-1",
    )

    assert result["status"] == "success"
    assert result["loop_id"]
    lid = LoopId(result["loop_id"])
    state = state_repo.get(lid)
    assert state is not None
    assert state.assessment_id == "assessment-1"
    assert state.phase is LoopPhase.INITIALIZING


def test_loop_create_without_grant_is_human_gated() -> None:
    result = handler_loop_create(
        _runtime(
            state_repo=InMemoryLoopStateRepository(),
            step_repo=InMemoryLoopStepRepository(),
        ),
        assessment_id="assessment-1",
    )
    assert result["status"] == "HUMAN_REQUIRED"


def test_loop_stop_with_grant_transitions_to_EMERGENCY_STOPPED() -> None:
    state_repo = InMemoryLoopStateRepository()
    step_repo = InMemoryLoopStepRepository()
    state = _loop(LoopId.new(), phase=LoopPhase.RUNNING)
    state_repo.save(state)

    result = handler_loop_stop(
        _runtime(state_repo=state_repo, step_repo=step_repo),
        loop_id=state.loop_id.value,
        grant_id="grant-1",
        actor="human",
    )

    assert result["status"] == "success"
    assert result["phase"] == LoopPhase.EMERGENCY_STOPPED.value
    stopped = state_repo.get(state.loop_id)
    assert stopped is not None
    assert stopped.phase is LoopPhase.EMERGENCY_STOPPED


def test_loop_stop_without_grant_is_human_gated() -> None:
    state_repo = InMemoryLoopStateRepository()
    state = _loop(LoopId.new())
    state_repo.save(state)

    result = handler_loop_stop(
        _runtime(
            state_repo=state_repo,
            step_repo=InMemoryLoopStepRepository(),
        ),
        loop_id=state.loop_id.value,
        actor="agent",
    )
    assert result["status"] == "HUMAN_REQUIRED"


def test_loop_stop_not_found_returns_NOT_FOUND() -> None:
    result = handler_loop_stop(
        _runtime(
            state_repo=InMemoryLoopStateRepository(),
            step_repo=InMemoryLoopStepRepository(),
        ),
        loop_id=LoopId.new().value,
        grant_id="grant-1",
        actor="human",
    )
    assert result["status"] == "error"
    assert result["code"] == "NOT_FOUND"
