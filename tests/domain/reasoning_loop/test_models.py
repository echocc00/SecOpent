"""Tests for ReasoningLoop domain models (v0.7.0 tracer bullet)."""
from __future__ import annotations

import re

import pytest

from secopent.domain.reasoning_loop.models import LoopId


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
