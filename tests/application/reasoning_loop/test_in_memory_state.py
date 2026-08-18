"""In-memory LoopStateRepository + LoopStepRepository."""
from __future__ import annotations

from datetime import UTC, datetime

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

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _state(loop_id: LoopId, phase: LoopPhase = LoopPhase.RUNNING) -> LoopState:
    return LoopState(
        loop_id=loop_id,
        assessment_id="asmt-1",
        phase=phase,
        policy_snapshot="sha256:" + "0" * 64,
        budget=LoopBudget.default(),
        context_hash="0" * 64,
        catalog_required_remaining=frozenset(),
        catalog_required_executed=frozenset(),
        consecutive_no_signal=0,
        consecutive_policy_rejected=0,
        started_at=_T0,
        last_step_at=None,
    )


def _step(loop_id: LoopId, step_number: int) -> LoopStep:
    pa = ProposeAction(
        action_type=LoopActionType.RUN_TOOL,
        payload={"tool_id": "nuclei", "parameters": {}},
        rationale="x" * 80,
        confidence=0.5,
    )
    return LoopStep(
        step_id=f"step-{step_number}",
        loop_id=loop_id,
        step_number=step_number,
        timestamp=_T0,
        context_hash_before="0" * 64,
        proposed_action=pa,
        propose_tokens_used=100,
        propose_latency_ms=150,
        propose_rationale=pa.rationale,
        schema_check_passed=True,
        policy_decision=PolicyDecision(verdict="allow", reason="ok"),
        permit_id="permit-1",
        tool_or_case_id="nuclei",
        execution_result_digest="sha256:" + "a" * 64,
        evidence_refs=(),
        observation_signals=(),
        catalog_class_matched=frozenset(),
        oracle_progressed=False,
        correlation_id="corr-1",
    )


def test_state_repo_get_returns_none_for_unknown_loop() -> None:
    repo = InMemoryLoopStateRepository()
    assert repo.get(LoopId(value="deadbeef")) is None


def test_state_repo_save_then_get() -> None:
    repo = InMemoryLoopStateRepository()
    state = _state(LoopId(value="abcd1234"))
    repo.save(state)
    fetched = repo.get(LoopId(value="abcd1234"))
    assert fetched == state


def test_state_repo_save_overwrites_with_same_id() -> None:
    repo = InMemoryLoopStateRepository()
    lid = LoopId(value="abcd1234")
    repo.save(_state(lid, phase=LoopPhase.RUNNING))
    repo.save(_state(lid, phase=LoopPhase.CONVERGED))
    assert repo.get(lid).phase is LoopPhase.CONVERGED


def test_step_repo_list_for_loop_returns_in_insertion_order() -> None:
    repo = InMemoryLoopStepRepository()
    lid = LoopId(value="abcd1234")
    repo.add(_step(lid, 1))
    repo.add(_step(lid, 2))
    repo.add(_step(lid, 3))
    listed = repo.list_for_loop(lid)
    assert [s.step_number for s in listed] == [1, 2, 3]


def test_step_repo_list_for_loop_isolates_by_loop_id() -> None:
    repo = InMemoryLoopStepRepository()
    a, b = LoopId(value="aaaa1111"), LoopId(value="bbbb2222")
    repo.add(_step(a, 1))
    repo.add(_step(b, 1))
    repo.add(_step(a, 2))
    assert [s.step_number for s in repo.list_for_loop(a)] == [1, 2]
    assert [s.step_number for s in repo.list_for_loop(b)] == [1]
