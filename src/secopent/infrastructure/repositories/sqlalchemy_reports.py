# src/secopent/infrastructure/repositories/sqlalchemy_reports.py
"""SqlAlchemy repository for rendered reports (§13)."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...domain.reports.models import Report, ReportSection, ReportStatus
from ..db.report_models import CoreReport


def _to_report(row: CoreReport) -> Report:
    return Report(
        id=row.id,
        assessment_id=row.assessment_id,
        title=row.title,
        sections=tuple(
            ReportSection(name=s["name"], content=s["content"]) for s in row.sections
        ),
        finding_count=row.finding_count,
        coverage_rate=row.coverage_rate,
        completeness_ok=row.completeness_ok,
        status=ReportStatus(row.status),
        digest=row.digest,
    )


def _from_report(report: Report) -> CoreReport:
    return CoreReport(
        id=report.id,
        assessment_id=report.assessment_id,
        title=report.title,
        sections=[{"name": s.name, "content": s.content} for s in report.sections],
        finding_count=report.finding_count,
        coverage_rate=report.coverage_rate,
        completeness_ok=report.completeness_ok,
        status=report.status.value,
        digest=report.digest,
    )


class SqlAlchemyReportRepository:
    """Persisted Report store."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, report: Report) -> None:
        self._session.merge(_from_report(report))

    def get(self, report_id: str) -> Report | None:
        row = self._session.get(CoreReport, report_id)
        return _to_report(row) if row else None

    def list_by_assessment(self, assessment_id: str) -> list[Report]:
        stmt = select(CoreReport).where(CoreReport.assessment_id == assessment_id)
        return [_to_report(row) for row in self._session.execute(stmt).scalars().all()]
