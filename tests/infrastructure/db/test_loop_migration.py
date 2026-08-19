"""ReasoningLoop persistence migration (v0.7.8, spec §12.1).

Upgrading a fresh DB to head must create ``core_reasoning_loops`` and
``core_loop_steps`` with the FULL LoopState/LoopStep column set (including the
extra counters + pause-tracking columns the spec §12.1 table design omits, so
``repo.get(state) == state`` round-trips with full fidelity).
"""
from __future__ import annotations

from pathlib import Path

import sqlalchemy as sa

from secopent.interfaces.cli.main import main


def _upgraded_engine(tmp_path: Path) -> sa.Engine:
    url = f"sqlite:///{(tmp_path / 'loops.db').as_posix()}"
    assert main(["db", "upgrade", "--db", url]) == 0
    return sa.create_engine(url)


# The exact LoopState field set persisted on core_reasoning_loops. Every field
# on the frozen ``LoopState`` dataclass (incl. the v0.7.7 pause/plaus fields)
# must be present so a save→get round-trip reconstructs an equal instance.
_LOOP_STATE_COLUMNS = frozenset(
    {
        "loop_id",
        "assessment_id",
        "phase",
        "policy_snapshot",
        "budget_state",
        "context_hash",
        "catalog_required_remaining",
        "catalog_required_executed",
        "consecutive_no_signal",
        "consecutive_policy_rejected",
        "started_at",
        "last_step_at",
        "ended_at",
        "pause_attempts",
        "paused_at",
        "resumed_at",
        "correlation_id",
    }
)

_LOOP_STEP_COLUMNS = frozenset(
    {
        "step_id",
        "loop_id",
        "step_number",
        "timestamp",
        "context_hash_before",
        "proposed_action",
        "propose_tokens_used",
        "propose_latency_ms",
        "propose_rationale",
        "schema_check_passed",
        "policy_decision",
        "permit_id",
        "tool_or_case_id",
        "execution_result",
        "evidence_refs",
        "observation_signals",
        "catalog_class_matched",
        "oracle_progressed",
        "correlation_id",
    }
)


def test_migration_creates_loop_tables(tmp_path) -> None:  # type: ignore[no-untyped-def]
    engine = _upgraded_engine(tmp_path)
    inspector = sa.inspect(engine)
    tables = set(inspector.get_table_names())
    assert "core_reasoning_loops" in tables
    assert "core_loop_steps" in tables


def test_loop_state_columns_present(tmp_path) -> None:  # type: ignore[no-untyped-def]
    engine = _upgraded_engine(tmp_path)
    cols = {c["name"] for c in sa.inspect(engine).get_columns("core_reasoning_loops")}
    assert cols >= _LOOP_STATE_COLUMNS


def test_loop_steps_columns_present(tmp_path) -> None:  # type: ignore[no-untyped-def]
    engine = _upgraded_engine(tmp_path)
    cols = {c["name"] for c in sa.inspect(engine).get_columns("core_loop_steps")}
    assert cols >= _LOOP_STEP_COLUMNS


def test_loop_steps_indexes(tmp_path) -> None:  # type: ignore[no-untyped-def]
    engine = _upgraded_engine(tmp_path)
    indexes = {i["name"] for i in sa.inspect(engine).get_indexes("core_loop_steps")}
    assert "ix_loop_steps_loop" in indexes
    loop_indexes = {i["name"] for i in sa.inspect(engine).get_indexes("core_reasoning_loops")}
    assert "ix_loops_assessment" in loop_indexes
