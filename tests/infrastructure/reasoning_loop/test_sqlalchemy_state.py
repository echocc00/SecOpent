"""SQLAlchemy LoopState/LoopStep repository round-trips (v0.7.8, spec §12.1).

The SQLAlchemy repos replace the in-memory stores in production. These tests
prove full-fidelity round-trips: ``repo.get(state) == state`` must hold for the
frozen ``LoopState`` dataclass (incl. counters + v0.7.7 pause fields), and
``LoopStep`` must reconstruct its ``ProposeAction`` (pydantic) + ``PolicyDecision``
(dataclass) faithfully.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

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
from secopent.infrastructure.db import session as _session  # noqa: F401 - registers models
from secopent.infrastructure.db.core_models import CoreBase
from secopent.infrastructure.reasoning_loop.sqlalchemy_state import (
    SqlAlchemyLoopStateRepository,
    SqlAlchemyLoopStepRepository,
)


@pytest.fixture
def session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    CoreBase.metadata.create_all(engine)
    s = Session(engine)
    yield s
    s.close()
    engine.dispose()


def _state(
    *,
    loop_id: str = "abcd1234",
    phase: LoopPhase = LoopPhase.RUNNING,
    consecutive_no_signal: int = 0,
    consecutive_policy_rejected: int = 0,
    last_step_at: datetime | None = None,
    pause_attempts: int = 0,
    paused_at: datetime | None = None,
    resumed_at: datetime | None = None,
    started_at: datetime | None = None,
) -> LoopState:
    return LoopState(
        loop_id=LoopId(value=loop_id),
        assessment_id="asmt-1",
        phase=phase,
        policy_snapshot="sha256:" + "0" * 64,
        budget=LoopBudget(max_steps=50, max_total_tokens=200_000, max_wall_seconds=1800,
                          steps_used=3, tokens_used=1200, wall_seconds_used=90),
        context_hash="a" * 64,
        catalog_required_remaining=frozenset({"web:xss", "web:sqli"}),
        catalog_required_executed=frozenset({"web:dir-list"}),
        consecutive_no_signal=consecutive_no_signal,
        consecutive_policy_rejected=consecutive_policy_rejected,
        started_at=started_at or datetime(2026, 1, 1, tzinfo=UTC),
        last_step_at=last_step_at,
        pause_attempts=pause_attempts,
        paused_at=paused_at,
        resumed_at=resumed_at,
    )


def _propose_action() -> ProposeAction:
    return ProposeAction(
        action_type=LoopActionType.RUN_TOOL,
        payload={"tool_id": "nuclei", "parameters": {"tags": ["sql-injection"]}},
        rationale="Catalog floor for SQLi not yet run on /api/users endpoint.",
        confidence=0.7,
    )


def _step(
    *,
    loop_id: str = "deadbeef",
    step_number: int = 1,
    step_id: str | None = None,
) -> LoopStep:
    pa = _propose_action()
    return LoopStep(
        step_id=step_id or f"step-{loop_id}-{step_number}",
        loop_id=LoopId(value=loop_id),
        step_number=step_number,
        timestamp=datetime(2026, 1, 1, step_number, tzinfo=UTC),
        context_hash_before="c" * 64,
        proposed_action=pa,
        propose_tokens_used=120,
        propose_latency_ms=200,
        propose_rationale=pa.rationale,
        schema_check_passed=True,
        policy_decision=PolicyDecision(verdict="allow", reason="in scope", deny_code=None),
        permit_id="permit-1",
        tool_or_case_id="nuclei",
        execution_result_digest="sha256:" + "a" * 64,
        evidence_refs=("ev-1", "ev-2"),
        observation_signals=("new_endpoint:/api/users",),
        catalog_class_matched=frozenset({"web:sqli"}),
        oracle_progressed=True,
        correlation_id="corr-1",
    )


class TestSqlAlchemyLoopStateRepository:
    def test_save_get_round_trip_equal(self, session: Session) -> None:
        repo = SqlAlchemyLoopStateRepository(session)
        state = _state(
            loop_id="abcd1234",
            phase=LoopPhase.PAUSED,
            consecutive_no_signal=2,
            consecutive_policy_rejected=1,
            last_step_at=datetime(2026, 1, 1, 5, tzinfo=UTC),
            pause_attempts=2,
            paused_at=datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
            resumed_at=datetime(2026, 1, 1, 10, 30, tzinfo=UTC),
        )
        repo.save(state)
        assert repo.get(state.loop_id) == state

    def test_get_missing_returns_none(self, session: Session) -> None:
        repo = SqlAlchemyLoopStateRepository(session)
        assert repo.get(LoopId(value="ffffffff")) is None

    def test_overwrite_same_loop_single_row(self, session: Session) -> None:
        repo = SqlAlchemyLoopStateRepository(session)
        s1 = _state(loop_id="abcd1234", phase=LoopPhase.INITIALIZING, pause_attempts=0)
        s2 = _state(loop_id="abcd1234", phase=LoopPhase.COMPLETED, pause_attempts=1)
        repo.save(s1)
        repo.save(s2)
        assert repo.get(LoopId(value="abcd1234")) == s2


class TestSqlAlchemyLoopStepRepository:
    def test_add_and_list_for_loop(self, session: Session) -> None:
        step_repo = SqlAlchemyLoopStepRepository(session)
        state_repo = SqlAlchemyLoopStateRepository(session)
        state_repo.save(_state(loop_id="deadbeef"))
        step = _step(loop_id="deadbeef", step_number=1)
        step_repo.add(step)
        assert [s.step_id for s in step_repo.list_for_loop(LoopId(value="deadbeef"))] == [
            step.step_id
        ]

    def test_ordered_by_step_number_when_added_out_of_order(self, session: Session) -> None:
        step_repo = SqlAlchemyLoopStepRepository(session)
        state_repo = SqlAlchemyLoopStateRepository(session)
        state_repo.save(_state(loop_id="deadbeef"))
        s1 = _step(loop_id="deadbeef", step_number=1)
        s0 = _step(loop_id="deadbeef", step_number=0, step_id="step-deadbeef-0")
        step_repo.add(s1)
        step_repo.add(s0)
        steps = step_repo.list_for_loop(LoopId(value="deadbeef"))
        assert [s.step_number for s in steps] == [0, 1]

    def test_round_trip_step_proposal_and_policy(self, session: Session) -> None:
        step_repo = SqlAlchemyLoopStepRepository(session)
        state_repo = SqlAlchemyLoopStateRepository(session)
        state_repo.save(_state(loop_id="deadbeef"))
        step = _step(loop_id="deadbeef", step_number=1)
        step_repo.add(step)
        [back] = step_repo.list_for_loop(LoopId(value="deadbeef"))
        assert back.proposed_action == step.proposed_action
        assert back.policy_decision == step.policy_decision
        assert back.proposed_action.action_type is LoopActionType.RUN_TOOL
        assert tuple(back.evidence_refs) == step.evidence_refs
        assert back.catalog_class_matched == step.catalog_class_matched
