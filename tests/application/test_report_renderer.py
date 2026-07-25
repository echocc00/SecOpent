"""TDD tests for ReportRenderer (M4 Task 8, §13 data-driven + redaction)."""
from __future__ import annotations

from secopent.application.report_renderer import ReportData, ReportRenderer
from secopent.domain.adapters.contracts import Severity
from secopent.domain.findings.models import Finding, FindingStatus
from secopent.infrastructure.evidence_store.redaction import RedactionEngine
from secopent.infrastructure.report_templates.renderer import Jinja2TemplateRenderer

_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def _renderer() -> ReportRenderer:
    return ReportRenderer(Jinja2TemplateRenderer(), RedactionEngine())


def _finding(*, status: FindingStatus = FindingStatus.VALIDATED) -> Finding:
    return Finding(
        id="f1",
        fingerprint="sha256:" + "a" * 64,
        title="SQL injection in /login",
        asset="https://x.test/login",
        severity=Severity.HIGH,
        cwe=("CWE-89",),
        evidence_ids=("ev-1",),
        status=status,
    )


def _data(**overrides: object) -> ReportData:
    base: dict[str, object] = {
        "assessment_id": "assess-1",
        "title": "Pentest Report",
        "scope_summary": "Authorized test of https://x.test",
        "method": "Catalog-driven active assessment.",
        "findings": (_finding(),),
        "coverage_rate": 1.0,
        "uncovered_classes": (),
        "evidence_digests": ("sha256:" + "e" * 64,),
        "assets": ("https://x.test",),
    }
    base.update(overrides)
    return ReportData(**base)  # type: ignore[arg-type]


def test_render_produces_all_sections() -> None:
    report = _renderer().render(_data(), report_id="rep-1")
    names = {s.name for s in report.sections}
    assert names == {
        "executive_summary",
        "scope",
        "method",
        "asset_inventory",
        "findings",
        "evidence",
        "coverage_matrix",
        "appendix",
    }


def test_findings_section_is_data_driven() -> None:
    report = _renderer().render(_data(), report_id="rep-1")
    findings_md = report.section("findings").content
    assert "SQL injection in /login" in findings_md
    assert "high" in findings_md  # severity
    assert "https://x.test/login" in findings_md  # asset
    assert "parameterized queries" in findings_md  # CWE-89 remediation
    assert "ev-1" in findings_md  # evidence traceability


def test_completeness_gate_passes_when_all_green() -> None:
    report = _renderer().render(_data(), report_id="rep-1")
    assert report.completeness_ok is True


def test_completeness_fails_on_uncovered_class() -> None:
    report = _renderer().render(
        _data(coverage_rate=0.66, uncovered_classes=("ssrf",)), report_id="rep-1"
    )
    assert report.completeness_ok is False


def test_completeness_fails_on_unverified_finding() -> None:
    report = _renderer().render(
        _data(findings=(_finding(status=FindingStatus.CANDIDATE),)), report_id="rep-1"
    )
    assert report.completeness_ok is False


def test_scope_narrative_is_redacted() -> None:
    data = _data(scope_summary=f"test with credential {_AWS_KEY} in scope")
    report = _renderer().render(data, report_id="rep-1")
    scope_md = report.section("scope").content
    assert _AWS_KEY not in scope_md
    assert "[REDACTED:aws_access_key]" in scope_md


def test_coverage_matrix_shows_rate() -> None:
    report = _renderer().render(_data(coverage_rate=1.0), report_id="rep-1")
    assert "100%" in report.section("coverage_matrix").content


def test_report_digest_present_and_stable() -> None:
    a = _renderer().render(_data(), report_id="rep-1")
    b = _renderer().render(_data(), report_id="rep-1")
    assert a.digest.startswith("sha256:")
    assert a.digest == b.digest
