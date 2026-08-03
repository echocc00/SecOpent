# src/secopent/interfaces/api/routers/reports.py
"""Reports resource router (Phase A P1, W1): data-driven assessment reports.

Surface over ``SqlAlchemyReportRepository``:
- ``POST /reports`` - render + persist a report for an assessment;
- ``GET /reports?assessment_id=`` - reports rendered for an assessment;
- ``GET /reports/{report_id}`` - one report with its sections.

Reports are rendered from Findings/Evidence (never hand-written numbers) by the
ReportRenderer, with redaction re-applied at render time. Coverage rate is read
from the ``assessment.completed`` audit payload (written by the execution layer).
"""
from __future__ import annotations

import uuid
from dataclasses import replace

from fastapi import APIRouter, HTTPException, Request

from ....application.remote_model import DataClassification, RemoteModelGateway
from ....application.report_renderer import ReportData, ReportRenderer
from ....domain.common.canonical import utc_now
from ....domain.common.errors import DomainError
from ....domain.reports.models import Report, ReportSection
from ....infrastructure.evidence_store.redaction import RedactionEngine
from ....infrastructure.report_templates.renderer import Jinja2TemplateRenderer
from ....infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAssessmentRepository,
    SqlAlchemyAuditRepository,
    SqlAlchemyScopeRepository,
)
from ....infrastructure.repositories.sqlalchemy_findings import (
    SqlAlchemyFindingRepository,
)
from ....infrastructure.repositories.sqlalchemy_reports import SqlAlchemyReportRepository
from ..deps import DbSession
from ..schemas import ReportGenerate, ReportOut, ReportSectionOut

router = APIRouter(prefix="/reports", tags=["reports"])


def _coverage_from_audit(session: DbSession, assessment_id: str) -> tuple[float, tuple[str, ...]]:
    """Read the coverage rate recorded by the execution layer.

    ``execute_assessment`` writes ``coverage_rate`` + ``uncovered_classes`` into
    the ``assessment.completed`` audit payload. Returns (0.0, ()) when no such
    event exists (pre-coverage runs or not-yet-completed assessments).
    """
    events = SqlAlchemyAuditRepository(session).list_events()
    for event in reversed(events):
        if (
            event.action == "assessment.completed"
            and event.resource_id == assessment_id
            and "coverage_rate" in event.payload
        ):
            rate_raw = event.payload.get("coverage_rate", 0.0)
            uncovered_raw = event.payload.get("uncovered_classes", ())
            rate = float(rate_raw) if isinstance(rate_raw, int | float) else 0.0
            uncovered: tuple[str, ...] = (
                tuple(uncovered_raw) if isinstance(uncovered_raw, list | tuple) else ()
            )
            return rate, uncovered
    return 0.0, ()


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


def _polish_executive_summary(
    gateway: RemoteModelGateway, report: Report
) -> Report:
    """LLM-polish the executive summary narrative (§3.3).

    The LLM only polishes wording; the deterministic executive_summary section
    is preserved verbatim and the polish is added as a separate
    ``executive_summary_polished`` section. Numbers come from the deterministic
    layer - the LLM never recomputes them (LLM boundary). An empty reply (no
    LLM configured) leaves the report unchanged.
    """
    exec_section = report.section("executive_summary")
    if exec_section is None:
        return report
    prompt = (
        "Polish this security report executive summary for clarity and tone. "
        "Keep ALL numbers exactly as written; do not add or change any figures.\n\n"
        + exec_section.content
    )
    try:
        response = gateway.call(
            prompt, classification=DataClassification.INTERNAL, now=utc_now()
        )
    except DomainError:
        return report
    polished = response.text.strip()
    if not polished:
        return report
    sections = (*report.sections, ReportSection(
        name="executive_summary_polished", content=polished
    ))
    return replace(report, sections=sections)


@router.post("", status_code=201, response_model=ReportOut)
def generate_report(
    payload: ReportGenerate, request: Request, session: DbSession
) -> ReportOut:
    """Render + persist a data-driven report for an assessment."""
    assessment_repo = SqlAlchemyAssessmentRepository(session)
    assessment = assessment_repo.get(payload.assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="assessment not found")

    findings = SqlAlchemyFindingRepository(session).all(
        assessment_id=payload.assessment_id
    )
    snapshot = SqlAlchemyScopeRepository(session).get_snapshot(
        assessment.scope_snapshot_id
    )
    scope_summary = (
        "In scope: " + ", ".join(snapshot.include) if snapshot else "n/a"
    )
    # Coverage rate is recorded by the execution layer in the audit chain
    # (assessment.completed payload); fall back to 0.0 for pre-coverage runs.
    coverage_rate, uncovered_classes = _coverage_from_audit(session, payload.assessment_id)
    data = ReportData(
        assessment_id=payload.assessment_id,
        title=payload.title,
        scope_summary=scope_summary,
        method="Catalog-driven authorized assessment with oracle N/N verification.",
        findings=tuple(findings),
        coverage_rate=coverage_rate,
        uncovered_classes=uncovered_classes,
        evidence_digests=tuple(
            eid for f in findings for eid in f.evidence_ids
        ),
        assets=tuple(sorted({f.asset for f in findings})),
    )
    renderer = ReportRenderer(Jinja2TemplateRenderer(), RedactionEngine())
    report = renderer.render(data, report_id=f"rep-{uuid.uuid4().hex[:12]}")
    if payload.polish:
        report = _polish_executive_summary(request.app.state.model_gateway, report)
    SqlAlchemyReportRepository(session).add(report)
    return _to_out(report)


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
