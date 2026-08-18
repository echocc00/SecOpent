"""Tests for ReasoningLoop domain models (v0.7.0 tracer bullet)."""
from __future__ import annotations

import re

import pytest

from secopent.domain.reasoning_loop.models import LoopBudget, LoopId, LoopPhase


def test_loop_id_is_8_char_hex() -> None:
    lid = LoopId.new()
    assert isinstance(lid.value, str)
    assert re.fullmatch(r"[0-9a-f]{8}", lid.value), lid.value


def test_loop_id_new_is_unique() -> None:
    ids = {LoopId.new() for _ in range(1000)}
    assert len(ids) == 1000


def test_loop_id_value_object_is_immutable() -> None:
    lid = LoopId(value="abcd1234")
    with pytest.raises((AttributeError, TypeError)):
        lid.value = "deadbeef"  # type: ignore[misc]


def test_loop_id_equality_on_value() -> None:
    a = LoopId(value="abcd1234")
    b = LoopId(value="abcd1234")
    c = LoopId(value="00000000")
    assert a == b
    assert a != c
    assert hash(a) == hash(b)


def test_loop_id_rejects_invalid_value() -> None:
    with pytest.raises(ValueError):
        LoopId(value="not-hex!")
    with pytest.raises(ValueError):
        LoopId(value="abcdef")  # too short


def test_loop_phase_is_string_enum() -> None:
    assert LoopPhase.RUNNING.value == "running"
    assert str(LoopPhase.RUNNING) == "LoopPhase.RUNNING"
    # JSON-serializable (used in audit)
    import json

    assert json.loads(json.dumps(LoopPhase.RUNNING.value)) == "running"


def test_loop_phase_includes_required_states() -> None:
    required = {
        "INITIALIZING",
        "RUNNING",
        "CONVERGED",
        "CATALOG_FLOOR_DONE",
        "PAUSED",  # spec §6.3 skeleton
        "RESUMED",  # spec §6.3 skeleton
        "BUDGET_EXHAUSTED",
        "POLICY_BLOCKED",
        "EMERGENCY_STOPPED",
        "COMPLETED",
    }
    assert {p.name for p in LoopPhase} >= required


def test_loop_budget_defaults() -> None:
    b = LoopBudget.default()
    snap = b.snapshot()
    assert snap.steps_remaining == 50
    assert snap.tokens_remaining == 200_000
    assert snap.wall_seconds_remaining == 1800


def test_loop_budget_consume_decrements() -> None:
    b = LoopBudget.default()
    b2 = b.consume(steps=3, tokens=1000, wall_seconds=30)
    snap = b2.snapshot()
    assert snap.steps_remaining == 47
    assert snap.tokens_remaining == 199_000
    assert snap.wall_seconds_remaining == 1770


def test_loop_budget_consume_returns_new_instance() -> None:
    """Budget must be immutable (frozen dataclass)."""
    b = LoopBudget.default()
    b.consume(steps=1)
    # Original unchanged.
    assert b.snapshot().steps_remaining == 50


def test_loop_budget_exhaustion_predicates() -> None:
    b = LoopBudget.default()
    assert not b.exhausted()
    # Drain all three budgets.
    drained = LoopBudget(
        max_steps=50,
        max_total_tokens=200_000,
        max_wall_seconds=1800,
        steps_used=50,
        tokens_used=200_000,
        wall_seconds_used=1800,
    )
    assert drained.exhausted()
