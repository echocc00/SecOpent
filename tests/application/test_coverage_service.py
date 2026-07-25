"""TDD tests for CoverageService (M1 Task 13, §4.2).

The CoverageService answers: given an Assessment's Observations and the pinned
TestCatalog, which required test classes for an asset type were actually
executed (covered) and which were not? ``enforce_gate`` implements the
"zero uncovered required classes" gate that must pass before an Assessment can
close.

Coverage is matched deterministically: a required test class is *covered* when
at least one Observation's CWE or OWASP attribution intersects the class's
curated CWE/OWASP tuples. No LLM judgment is involved (LLM边界: coverage is a
deterministic CoverageMatrix decision).
"""
from __future__ import annotations

import pytest

from secopent.application.coverage import CoverageService
from secopent.domain.adapters.contracts import (
    AdapterSource,
    CoverageDomain,
    Observation,
    Severity,
)
from secopent.domain.catalog.models import AssetType, RequiredTestClass, TestCatalog
from secopent.domain.catalog.report import CoverageGapError, CoverageReport
from secopent.domain.policy.models import RiskClass

_SOURCE = AdapterSource(name="nuclei", version="3.0.0", template_version="1.0.0")


def _observation(*, cwe: tuple[str, ...] = (), owasp: tuple[str, ...] = ()) -> Observation:
    """Build a minimal Observation carrying only the coverage-relevant tuples."""
    return Observation(
        external_id="obs-1",
        asset_identity="https://example.test/",
        source=_SOURCE,
        rule_id="rule-1",
        rule_version="1.0.0",
        coverage_domain=CoverageDomain.WEB,
        title="finding",
        severity=Severity.MEDIUM,
        confidence=0.9,
        cwe=cwe,
        owasp=owasp,
    )


def _web_catalog() -> TestCatalog:
    return TestCatalog(
        version="2026.07",
        mappings={
            AssetType.WEB_APP: (
                RequiredTestClass(
                    id="sqli", cwe=("CWE-89",), owasp=("A03:2021",), risk=RiskClass.ACTIVE
                ),
                RequiredTestClass(
                    id="xss", cwe=("CWE-79",), owasp=("A03:2021",), risk=RiskClass.ACTIVE
                ),
                RequiredTestClass(
                    id="ssrf", cwe=("CWE-918",), owasp=("A10:2021",), risk=RiskClass.ACTIVE
                ),
            ),
        },
    )


def test_compute_marks_covered_and_uncovered_by_cwe() -> None:
    service = CoverageService()
    catalog = _web_catalog()
    observations = [
        _observation(cwe=("CWE-89",)),  # covers sqli
        _observation(cwe=("CWE-79",)),  # covers xss
        # ssrf (CWE-918) NOT executed
    ]

    report = service.compute(AssetType.WEB_APP, observations, catalog)

    assert isinstance(report, CoverageReport)
    assert report.asset_type is AssetType.WEB_APP
    assert set(report.required_classes) == {"sqli", "xss", "ssrf"}
    assert set(report.covered_classes) == {"sqli", "xss"}
    assert report.uncovered_classes == ("ssrf",)
    assert report.coverage_rate == pytest.approx(2 / 3)


def test_compute_matches_by_owasp_when_cwe_absent() -> None:
    service = CoverageService()
    catalog = _web_catalog()
    # Observation carries only OWASP A10:2021 -> must cover ssrf via OWASP match.
    observations = [_observation(owasp=("A10:2021",))]

    report = service.compute(AssetType.WEB_APP, observations, catalog)

    assert "ssrf" in report.covered_classes


def test_compute_empty_observations_all_uncovered() -> None:
    service = CoverageService()
    catalog = _web_catalog()

    report = service.compute(AssetType.WEB_APP, [], catalog)

    assert report.covered_classes == ()
    assert set(report.uncovered_classes) == {"sqli", "xss", "ssrf"}
    assert report.coverage_rate == 0.0


def test_compute_unknown_asset_type_has_no_required_classes() -> None:
    service = CoverageService()
    catalog = _web_catalog()  # only WEB_APP mapped

    report = service.compute(AssetType.CLOUD_ACCOUNT, [], catalog)

    assert report.required_classes == ()
    assert report.uncovered_classes == ()
    # Vacuously fully covered when nothing is required.
    assert report.coverage_rate == 1.0


def test_enforce_gate_raises_on_uncovered_required_class() -> None:
    service = CoverageService()
    catalog = _web_catalog()
    report = service.compute(AssetType.WEB_APP, [_observation(cwe=("CWE-89",))], catalog)

    with pytest.raises(CoverageGapError):
        service.enforce_gate(report)


def test_enforce_gate_passes_when_all_covered() -> None:
    service = CoverageService()
    catalog = _web_catalog()
    observations = [
        _observation(cwe=("CWE-89",)),
        _observation(cwe=("CWE-79",)),
        _observation(cwe=("CWE-918",)),
    ]
    report = service.compute(AssetType.WEB_APP, observations, catalog)

    # No exception.
    service.enforce_gate(report)
    assert report.uncovered_classes == ()
    assert report.coverage_rate == 1.0


def test_enforce_gate_passes_for_empty_required() -> None:
    service = CoverageService()
    catalog = _web_catalog()
    report = service.compute(AssetType.CLOUD_ACCOUNT, [], catalog)

    service.enforce_gate(report)  # no required classes -> gate trivially passes


def test_coverage_gap_error_carries_uncovered_classes() -> None:
    service = CoverageService()
    catalog = _web_catalog()
    report = service.compute(AssetType.WEB_APP, [], catalog)

    with pytest.raises(CoverageGapError) as excinfo:
        service.enforce_gate(report)
    # The error message names the unmet required classes for operators.
    assert "ssrf" in str(excinfo.value)


def test_coverage_report_is_immutable() -> None:
    service = CoverageService()
    report = service.compute(AssetType.WEB_APP, [], _web_catalog())
    with pytest.raises(AttributeError):
        report.coverage_rate = 1.0  # type: ignore[misc]


def test_coverage_gap_error_is_domain_error() -> None:
    from secopent.domain.common.errors import DomainError

    assert issubclass(CoverageGapError, DomainError)
