"""TDD tests for the Finding domain + fingerprint (M4 Task 2, §13 correlation).

A Finding is the reportable unit produced by correlating Observations. Its
``fingerprint`` is a deterministic digest of (asset + CWE + CVE) so the SAME
vulnerability reported by DIFFERENT tools collapses to one Finding (cross-tool
dedup). The fingerprint deliberately excludes the source/rule id so tools agree.
"""
from __future__ import annotations

import pytest

from secopent.domain.adapters.contracts import (
    AdapterSource,
    CoverageDomain,
    Observation,
    Severity,
)
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.findings.fingerprint import observation_fingerprint
from secopent.domain.findings.models import Finding, FindingStatus


def _observation(
    *,
    asset: str = "https://x.test/login",
    cwe: tuple[str, ...] = ("CWE-89",),
    cve: tuple[str, ...] = (),
    source_name: str = "nuclei",
    rule_id: str = "sqli-login",
    external_id: str = "obs-1",
) -> Observation:
    return Observation(
        external_id=external_id,
        asset_identity=asset,
        source=AdapterSource(name=source_name, version="1.0.0", template_version="1.0.0"),
        rule_id=rule_id,
        rule_version="1.0.0",
        coverage_domain=CoverageDomain.WEB,
        title="SQL injection",
        severity=Severity.HIGH,
        confidence=0.9,
        cwe=cwe,
        cve=cve,
    )


def test_finding_status_states() -> None:
    assert {s.value for s in FindingStatus} == {
        "draft",
        "candidate",
        "validated",
        "reported",
        "closed",
        "false_positive",
    }


def test_finding_requires_core_fields() -> None:
    with pytest.raises(DomainValidationError):
        Finding(id="", fingerprint="fp", title="t", asset="a", severity=Severity.HIGH)
    with pytest.raises(DomainValidationError):
        Finding(id="f", fingerprint="", title="t", asset="a", severity=Severity.HIGH)


def test_finding_defaults_to_draft() -> None:
    finding = Finding(id="f", fingerprint="fp", title="t", asset="a", severity=Severity.HIGH)
    assert finding.status is FindingStatus.DRAFT


def test_fingerprint_is_deterministic() -> None:
    assert observation_fingerprint(_observation()) == observation_fingerprint(_observation())


def test_fingerprint_differs_by_asset() -> None:
    a = observation_fingerprint(_observation(asset="https://x.test/login"))
    b = observation_fingerprint(_observation(asset="https://x.test/search"))
    assert a != b


def test_fingerprint_differs_by_cwe() -> None:
    a = observation_fingerprint(_observation(cwe=("CWE-89",)))
    b = observation_fingerprint(_observation(cwe=("CWE-79",)))
    assert a != b


def test_fingerprint_ignores_source_for_cross_tool_dedup() -> None:
    # Same vuln (asset + CWE) reported by nuclei vs zap -> same fingerprint.
    nuclei = observation_fingerprint(_observation(source_name="nuclei", rule_id="sqli-1"))
    zap = observation_fingerprint(_observation(source_name="zap", rule_id="42"))
    assert nuclei == zap


def test_fingerprint_cwe_order_independent() -> None:
    a = observation_fingerprint(_observation(cwe=("CWE-89", "CWE-200")))
    b = observation_fingerprint(_observation(cwe=("CWE-200", "CWE-89")))
    assert a == b
