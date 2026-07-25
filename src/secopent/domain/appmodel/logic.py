# src/secopent/domain/appmodel/logic.py
"""Model-driven logic test cases (§11.10, ADR-005/012).

The LogicTestGenerator deterministically derives five classes of logic tests
from a signed AppModel. Each generated test is a ``LogicTestCase`` carrying its
class, the AppModel digest it was derived from, the constructed inputs, and a
``signature`` = sha256(app_model_digest + test_class + strategy_version +
target) so the same model always yields the same signature (idempotent - the
CoverageMatrix dedupes on it and an AppModel micro-change regenerates only the
changed signatures).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum

from ..common.errors import DomainValidationError


class LogicTestClass(StrEnum):
    """The five model-driven logic test classes."""

    SKIP_STEP = "skip_step"
    OUT_OF_ORDER = "out_of_order"
    REPLAY = "replay"
    BOUNDARY = "boundary"
    INVARIANT_VIOLATION = "invariant_violation"


@dataclass(frozen=True, slots=True)
class LogicTestCase:
    """A single model-generated logic test."""

    test_class: LogicTestClass
    app_model_digest: str
    target: str
    description: str
    inputs: tuple[tuple[str, object], ...] = ()
    signature: str = ""

    def __post_init__(self) -> None:
        if not self.app_model_digest:
            raise DomainValidationError("LogicTestCase.app_model_digest must be non-empty")
        if not self.target:
            raise DomainValidationError("LogicTestCase.target must be non-empty")


def compute_signature(
    *,
    app_model_digest: str,
    test_class: LogicTestClass,
    strategy_version: str,
    target: str,
) -> str:
    """Deterministic signature: same inputs -> same signature (idempotency)."""
    payload = "|".join(
        [app_model_digest, test_class.value, strategy_version, target]
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
