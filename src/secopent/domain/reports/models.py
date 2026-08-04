# src/secopent/domain/reports/models.py
"""Report domain models (§13): a data-driven, traceable assessment report.

A Report is rendered from Findings/Evidence/CoverageMatrix - never hand-written
numbers. It is a fixed set of sections (executive summary, scope, method, asset
inventory, findings, evidence, remediation, coverage matrix, appendix). The
``completeness_ok`` flag captures the release gate: every section filled, zero
unverified findings, coverage matrix green, evidence digests present.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from ..common.canonical import canonical_digest
from ..common.errors import DomainValidationError


class ReportStatus(StrEnum):
    """Report lifecycle states."""

    DRAFT = "draft"
    RENDERED = "rendered"
    APPROVED = "approved"
    RELEASED = "released"


@dataclass(frozen=True, slots=True)
class ReportSection:
    """One chapter of the report."""

    name: str
    content: str


@dataclass(frozen=True, slots=True)
class Report:
    """A rendered, traceable assessment report."""

    id: str
    assessment_id: str
    title: str
    sections: tuple[ReportSection, ...]
    finding_count: int
    coverage_rate: float
    completeness_ok: bool
    status: ReportStatus = ReportStatus.RENDERED
    digest: str = ""

    def section(self, name: str) -> ReportSection | None:
        for section in self.sections:
            if section.name == name:
                return section
        return None

    def compute_digest(self) -> str:
        return canonical_digest(
            {
                "id": self.id,
                "assessment_id": self.assessment_id,
                "title": self.title,
                "sections": self.sections,
                "finding_count": self.finding_count,
                "coverage_rate": self.coverage_rate,
            }
        )

    def approve(self) -> Report:
        """RENDERED -> APPROVED (reviewer signs off). No backward transitions."""
        if self.status is not ReportStatus.RENDERED:
            raise DomainValidationError(
                f"cannot approve a report in {self.status.value} state"
            )
        return replace(self, status=ReportStatus.APPROVED)

    def release(self) -> Report:
        """APPROVED -> RELEASED. Requires completeness_ok (release gate)."""
        if self.status is not ReportStatus.APPROVED:
            raise DomainValidationError(
                f"cannot release a report in {self.status.value} state"
            )
        if not self.completeness_ok:
            raise DomainValidationError(
                "cannot release an incomplete report (completeness_ok is False)"
            )
        return replace(self, status=ReportStatus.RELEASED)
