# src/secopent/interfaces/api/routers/reports.py
"""Reports resource router (Phase A P1, W1): data-driven assessment reports.

Read-only surface over ``SqlAlchemyReportRepository``:
- ``GET /reports?assessment_id=`` - reports rendered for an assessment;
- ``GET /reports/{report_id}`` - one report with its sections.

Reports are rendered from Findings/Evidence/CoverageMatrix (never hand-written
numbers); rendering is performed by the ReportRenderer, not exposed as a naive
POST here.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ....domain.reports.models import Report
from ....infrastructure.repositories.sqlalchemy_reports import SqlAlchemyReportRepository
from ..deps import DbSession
from ..schemas import ReportOut, ReportSectionOut

router = APIRouter(prefix="/reports", tags=["reports"])


def _to_out(report: Report) -> ReportOut:
    return ReportOut(
        id=report.id,
        assessment_id=report.assessment_id,
        title=report.title,
        sections=[
            ReportSectionOut(name=s.name, content=s.content) for s in report.sections
        ],
        finding_count=report.finding_count,
        coverage_rate=report.coverage_rate,
        completeness_ok=report.completeness_ok,
        status=report.status.value,
        digest=report.digest,
    )


@router.get("", response_model=list[ReportOut])
def list_reports(assessment_id: str, session: DbSession) -> list[ReportOut]:
    reports = SqlAlchemyReportRepository(session).list_by_assessment(assessment_id)
    return [_to_out(r) for r in reports]


@router.get("/{report_id}", response_model=ReportOut)
def get_report(report_id: str, session: DbSession) -> ReportOut:
    report = SqlAlchemyReportRepository(session).get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="report not found")
    return _to_out(report)
