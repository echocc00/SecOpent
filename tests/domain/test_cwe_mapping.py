"""CWE -> VulnType mapping for the oracle (W3-A T2)."""
from __future__ import annotations

from secopent.domain.verification.cwe_mapping import vuln_type_for_cwe, vuln_type_for_cwes
from secopent.domain.verification.models import VulnType


def test_known_cwe_maps_to_vuln_type() -> None:
    assert vuln_type_for_cwe("CWE-89") is VulnType.SQLI
    assert vuln_type_for_cwe("CWE-79") is VulnType.XSS
    assert vuln_type_for_cwe("CWE-918") is VulnType.SSRF
    assert vuln_type_for_cwe("CWE-611") is VulnType.XXE
    assert vuln_type_for_cwe("CWE-502") is VulnType.DESERIALIZATION
    assert vuln_type_for_cwe("CWE-639") is VulnType.IDOR
    assert vuln_type_for_cwe("CWE-22") is VulnType.PATH_TRAVERSAL
    assert vuln_type_for_cwe("CWE-287") is VulnType.AUTH_BYPASS
    assert vuln_type_for_cwe("CWE-269") is VulnType.PRIVILEGE_ESCALATION
    assert vuln_type_for_cwe("CWE-521") is VulnType.WEAK_CREDENTIALS
    assert vuln_type_for_cwe("CWE-78") is VulnType.RCE


def test_unknown_cwe_returns_none() -> None:
    assert vuln_type_for_cwe("CWE-999") is None
    assert vuln_type_for_cwe("") is None


def test_first_mappable_cwe_wins_for_findings() -> None:
    """A finding may carry multiple CWEs; the first mappable one wins."""
    assert vuln_type_for_cwes(("CWE-999", "CWE-89")) is VulnType.SQLI
    assert vuln_type_for_cwes(("CWE-79", "CWE-89")) is VulnType.XSS  # order matters
    assert vuln_type_for_cwes(("CWE-999", "CWE-888")) is None
    assert vuln_type_for_cwes(()) is None
