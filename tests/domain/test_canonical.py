# tests/domain/test_canonical.py
from __future__ import annotations

from datetime import datetime

import pytest

from secopent.domain.common.canonical import canonical_digest, canonical_json, utc_now
from secopent.domain.common.errors import DomainValidationError


def test_digest_ignores_dict_insertion_order() -> None:
    left = {"b": [2, 1], "a": "é"}
    right = {"a": "é", "b": [2, 1]}
    assert canonical_json(left) == '{"a":"é","b":[2,1]}'
    assert canonical_digest(left) == canonical_digest(right)


def test_rejects_naive_datetime() -> None:
    with pytest.raises(DomainValidationError, match="timezone-aware"):
        canonical_json({"at": datetime(2026, 7, 25)})


def test_utc_now_is_aware() -> None:
    assert utc_now().tzinfo is not None


def test_digest_prefix() -> None:
    assert canonical_digest({"x": 1}).startswith("sha256:")
