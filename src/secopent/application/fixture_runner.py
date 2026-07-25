# src/secopent/application/fixture_runner.py
"""FixtureRunner: validate a case's five fixture classes before publish (§11.7).

Every case must ship five fixture classes - positive (the case detects the
vuln), negative (it does not), timeout, scope_deny, and malformed (the last
three handled gracefully: not detected and no crash). Intrusive cases
additionally require range / before-after / cleanup / max-impact fixtures. A
case may publish only when all required fixtures are present AND behave as
expected.

Each ``CaseFixture`` carries the observed ``detected`` outcome of running the
case against that fixture's scenario (produced by the case engine / E2E run);
the runner checks presence and expected behavior.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from ..domain.cases.models import CaseDefinition
from ..domain.policy.models import RiskClass

# The five fixture classes every case must ship.
REQUIRED_FIXTURE_KINDS: tuple[str, ...] = (
    "positive",
    "negative",
    "timeout",
    "scope_deny",
    "malformed",
)

# Extra fixture classes required for Intrusive cases (§11.7).
INTRUSIVE_EXTRA_KINDS: tuple[str, ...] = (
    "range",
    "before_after",
    "cleanup",
    "max_impact",
)

# Expected ``detected`` outcome per fixture kind (None = presence-only check).
_EXPECTED_DETECTED: dict[str, bool] = {
    "positive": True,
    "negative": False,
    "timeout": False,
    "scope_deny": False,
    "malformed": False,
}


@dataclass(frozen=True, slots=True)
class CaseFixture:
    """One fixture scenario result: its class and whether the case detected."""

    kind: str
    detected: bool


@dataclass
class FixtureResult:
    """Outcome of fixture validation."""

    passed: bool
    missing_kinds: tuple[str, ...] = ()
    failures: tuple[str, ...] = field(default_factory=tuple)


class FixtureRunner:
    """Validate that a case's required fixtures are present and behave."""

    def run(
        self, case: CaseDefinition, fixtures: Sequence[CaseFixture]
    ) -> FixtureResult:
        """Return a FixtureResult; ``passed`` is True iff all fixtures satisfy."""
        required = set(REQUIRED_FIXTURE_KINDS)
        if case.risk is RiskClass.INTRUSIVE:
            required |= set(INTRUSIVE_EXTRA_KINDS)

        present = {fixture.kind for fixture in fixtures}
        missing = tuple(sorted(required - present))

        failures: list[str] = []
        for fixture in fixtures:
            expected = _EXPECTED_DETECTED.get(fixture.kind)
            if expected is not None and fixture.detected is not expected:
                failures.append(
                    f"{fixture.kind}: expected detected={expected}, "
                    f"got detected={fixture.detected}"
                )

        passed = not missing and not failures
        return FixtureResult(passed=passed, missing_kinds=missing, failures=tuple(failures))
