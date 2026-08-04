"""Report state machine + release invariant (W3-D T1)."""
from __future__ import annotations

import pytest

from secopent.domain.common.errors import DomainValidationError
from secopent.domain.reports.models import Report, ReportSection, ReportStatus


def _report(
    *,
    status: ReportStatus = ReportStatus.RENDERED,
    completeness_ok: bool = True,
) -> Report:
    return Report(
        id="r-1",
        assessment_id="a-1",
        title="t",
        sections=(ReportSection(name="exec", content="x"),),
        finding_count=1,
        coverage_rate=1.0,
        completeness_ok=completeness_ok,
        status=status,
        digest="sha256:abc",
    )


def test_rendered_can_approve() -> None:
    r = _report(status=ReportStatus.RENDERED).approve()
    assert r.status is ReportStatus.APPROVED


def test_approved_can_release_when_complete() -> None:
    r = _report(status=ReportStatus.APPROVED, completeness_ok=True).release()
    assert r.status is ReportStatus.RELEASED


def test_release_rejects_incomplete_report() -> None:
    r = _report(status=ReportStatus.APPROVED, completeness_ok=False)
    with pytest.raises(DomainValidationError):
        r.release()


def test_release_requires_approved_state() -> None:
    r = _report(status=ReportStatus.RENDERED)  # not yet approved
    with pytest.raises(DomainValidationError):
        r.release()


def test_no_backward_transition_from_released() -> None:
    r = _report(status=ReportStatus.RELEASED)
    with pytest.raises(DomainValidationError):
        r.approve()  # can't go back to APPROVED from RELEASED


def test_approve_requires_rendered_state() -> None:
    r = _report(status=ReportStatus.DRAFT)
    with pytest.raises(DomainValidationError):
        r.approve()
