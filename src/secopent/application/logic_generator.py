# src/secopent/application/logic_generator.py
"""LogicTestGenerator: orchestrate model-driven logic test generation (§11.10).

The generator runs the registered strategies (RESTler sequence tests,
Schemathesis boundary tests, self-built invariant tests) over a signed AppModel
and collects the five logic test classes. Generation is a pure function of the
AppModel: every case carries a deterministic signature, so the same model always
yields the same signatures (idempotent - CoverageMatrix dedupes on them) and an
AppModel micro-change regenerates only the changed signatures (incremental diff).

The LLM is never in this path - generation is deterministic from the signed,
human-validated model (LLM边界).
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol, runtime_checkable

from ..domain.appmodel.logic import LogicTestCase
from ..domain.appmodel.models import AppModel


@runtime_checkable
class LogicGenerationStrategy(Protocol):
    """A strategy that derives logic test cases from an AppModel."""

    strategy_version: str

    def generate(self, app_model: AppModel) -> tuple[LogicTestCase, ...]: ...


class LogicTestGenerator:
    """Orchestrate logic-test generation across strategies."""

    def __init__(self, strategies: Sequence[LogicGenerationStrategy]) -> None:
        self._strategies = list(strategies)

    def generate(self, app_model: AppModel) -> tuple[LogicTestCase, ...]:
        """Generate all logic test cases for the model (deterministic)."""
        cases: list[LogicTestCase] = []
        for strategy in self._strategies:
            cases.extend(strategy.generate(app_model))
        return tuple(cases)

    def generate_incremental(
        self, app_model: AppModel, known_signatures: Iterable[str]
    ) -> tuple[LogicTestCase, ...]:
        """Generate only cases whose signature is new (not in known_signatures).

        Used after an AppModel micro-change: unchanged cases keep their signature
        and are skipped, so only the affected tests are regenerated/re-run.
        """
        known = set(known_signatures)
        return tuple(
            case for case in self.generate(app_model) if case.signature not in known
        )
