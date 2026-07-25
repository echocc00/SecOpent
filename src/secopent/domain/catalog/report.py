# src/secopent/domain/catalog/report.py
"""Coverage evaluation report and the deterministic coverage rule (§4.2).

This module holds the pure domain logic that answers: given the required test
classes for an asset type (from the pinned TestCatalog) and the Observations an
Assessment actually produced, which required classes were *covered* and which
were *uncovered*?

A required test class is **covered** when at least one Observation's CWE or
OWASP attribution intersects the class's curated CWE/OWASP tuples. This is a
deterministic set-intersection rule - no LLM judgment is involved (LLM边界:
coverage is a CoverageMatrix decision, never a model call).
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ..adapters.contracts import Observation
from ..common.errors import DomainError, DomainValidationError
from .models import AssetType, RequiredTestClass


class CoverageGapError(DomainError):
    """Raised when the coverage gate fails (>= 1 uncovered required class).

    Subclasses DomainError so the error layer classifies coverage-gate failures
    alongside other deterministic domain errors. The message names the unmet
    required classes for operators.
    """


@dataclass(frozen=True, slots=True)
class CoverageReport:
    """Result of evaluating coverage for one asset type.

    ``required_classes`` / ``covered_classes`` / ``uncovered_classes`` are test
    class ids (see RequiredTestClass.id). ``coverage_rate`` is
    covered / required in [0.0, 1.0]; it is 1.0 when nothing is required
    (vacuously fully covered).
    """

    asset_type: AssetType
    required_classes: tuple[str, ...]
    covered_classes: tuple[str, ...]
    uncovered_classes: tuple[str, ...]
    coverage_rate: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.coverage_rate <= 1.0:
            raise DomainValidationError("CoverageReport.coverage_rate must be in [0.0, 1.0]")


def _class_covered(required: RequiredTestClass, observations: Iterable[Observation]) -> bool:
    """A required class is covered when any observation's CWE/OWASP intersects it."""
    req_cwe = set(required.cwe)
    req_owasp = set(required.owasp)
    for obs in observations:
        if req_cwe.intersection(obs.cwe) or req_owasp.intersection(obs.owasp):
            return True
    return False


def compute_coverage(
    asset_type: AssetType,
    required: tuple[RequiredTestClass, ...],
    observations: Iterable[Observation],
) -> CoverageReport:
    """Evaluate which required test classes are covered by the observations.

    Args:
        asset_type: the asset type the report is scoped to.
        required: the required test classes (from TestCatalog.required_for).
        observations: the Assessment's normalized Observations.

    Returns:
        A CoverageReport partitioning required class ids into covered/uncovered
        with the coverage rate. Empty ``required`` yields rate 1.0.
    """
    obs = tuple(observations)
    covered: list[str] = []
    uncovered: list[str] = []
    for cls in required:
        if _class_covered(cls, obs):
            covered.append(cls.id)
        else:
            uncovered.append(cls.id)
    required_ids = tuple(cls.id for cls in required)
    rate = len(covered) / len(required) if required else 1.0
    return CoverageReport(
        asset_type=asset_type,
        required_classes=required_ids,
        covered_classes=tuple(covered),
        uncovered_classes=tuple(uncovered),
        coverage_rate=rate,
    )
