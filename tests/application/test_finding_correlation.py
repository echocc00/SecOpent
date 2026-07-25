"""TDD tests for FindingCorrelation (M4 Task 2, §13 deterministic dedup)."""
from __future__ import annotations

from secopent.application.finding_correlation import FindingCorrelation
from secopent.domain.adapters.contracts import (
    AdapterSource,
    CoverageDomain,
    Observation,
    Severity,
)
from secopent.domain.findings.models import Finding, FindingStatus


def _obs(
    external_id: str,
    *,
    asset: str = "https://x.test/login",
    cwe: tuple[str, ...] = ("CWE-89",),
    source_name: str = "nuclei",
    severity: Severity = Severity.HIGH,
) -> Observation:
    return Observation(
        external_id=external_id,
        asset_identity=asset,
        source=AdapterSource(name=source_name, version="1.0.0", template_version="1.0.0"),
        rule_id="rule",
        rule_version="1.0.0",
        coverage_domain=CoverageDomain.WEB,
        title="SQL injection",
        severity=severity,
        confidence=0.9,
        cwe=cwe,
    )


def test_cross_tool_same_vuln_merges_to_one_finding() -> None:
    observations = [
        _obs("obs-nuclei", source_name="nuclei"),
        _obs("obs-zap", source_name="zap"),
    ]
    findings = FindingCorrelation().correlate(observations)
    assert len(findings) == 1
    assert set(findings[0].observation_ids) == {"obs-nuclei", "obs-zap"}


def test_distinct_vulns_stay_separate() -> None:
    observations = [
        _obs("obs-1", cwe=("CWE-89",)),
        _obs("obs-2", cwe=("CWE-79",)),
    ]
    findings = FindingCorrelation().correlate(observations)
    assert len(findings) == 2


def test_finding_merges_cwe_union() -> None:
    observations = [
        _obs("obs-1", cwe=("CWE-89",)),
        _obs("obs-2", source_name="zap", cwe=("CWE-89", "CWE-200")),
    ]
    findings = FindingCorrelation().correlate(observations)
    assert set(findings[0].cwe) == {"CWE-89", "CWE-200"}


def test_finding_severity_is_max_of_group() -> None:
    observations = [
        _obs("obs-1", severity=Severity.MEDIUM),
        _obs("obs-2", source_name="zap", severity=Severity.CRITICAL),
    ]
    findings = FindingCorrelation().correlate(observations)
    assert findings[0].severity is Severity.CRITICAL


def test_correlated_findings_are_candidates() -> None:
    findings = FindingCorrelation().correlate([_obs("obs-1")])
    assert findings[0].status is FindingStatus.CANDIDATE
    assert isinstance(findings[0], Finding)


def test_empty_observations_yield_no_findings() -> None:
    assert FindingCorrelation().correlate([]) == ()
