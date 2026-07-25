# src/secopent/application/coverage.py
"""CoverageService: compute the coverage report and enforce the coverage gate (§4.2).

The service orchestrates the deterministic domain coverage rule
(``domain.catalog.report.compute_coverage``) and the "zero uncovered required
classes" gate that an Assessment must pass before it can close.

The service is stateless: the pinned TestCatalog and the Assessment's
Observations are passed to ``compute`` (M1 uses an in-memory observation list;
M4 will source observations from a repository). Coverage is a deterministic
CoverageMatrix decision - no LLM judgment is involved (LLM边界).
"""
from __future__ import annotations

from collections.abc import Iterable

from ..domain.adapters.contracts import Observation
from ..domain.catalog.models import AssetType, TestCatalog
from ..domain.catalog.report import (
    CoverageGapError,
    CoverageReport,
    compute_coverage,
)


class CoverageService:
    """Compute coverage reports and enforce the coverage gate."""

    def compute(
        self,
        asset_type: AssetType,
        observations: Iterable[Observation],
        catalog: TestCatalog,
    ) -> CoverageReport:
        """Evaluate which required test classes for ``asset_type`` are covered.

        Pulls the required classes from the pinned catalog and delegates the
        deterministic CWE/OWASP matching to the domain rule.
        """
        required = catalog.required_for(asset_type)
        return compute_coverage(asset_type, required, observations)

    def enforce_gate(self, report: CoverageReport) -> None:
        """Raise CoverageGapError if any required test class is uncovered.

        The gate implements "0 未执行必修类才能结题": an Assessment may only
        close when every required test class for its asset type was executed.
        """
        if report.uncovered_classes:
            missing = ", ".join(report.uncovered_classes)
            raise CoverageGapError(
                f"coverage gate failed for {report.asset_type.value}: "
                f"uncovered required classes: {missing}"
            )
