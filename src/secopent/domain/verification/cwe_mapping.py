"""CWE -> VulnType curation for the oracle (W3-A T2).

Maps the CWE a correlated Finding carries to one of the 14 VulnTypes the
oracle knows how to verify (see VerificationMethodRegistry). Findings whose
CWEs have no mapping are not oracle-verifiable and stay as unconfirmed
Findings (oracle_verdict remains PENDING).

Only CWEs with an unambiguous VulnType are listed; ambiguous or info-class
CWEs are deliberately omitted so the oracle never verifies a finding against
the wrong recipe.
"""
from __future__ import annotations

from collections.abc import Sequence

from .models import VulnType

_CWE_TO_VULN: dict[str, VulnType] = {
    "CWE-89": VulnType.SQLI,
    "CWE-77": VulnType.RCE,
    "CWE-78": VulnType.RCE,
    "CWE-918": VulnType.SSRF,
    "CWE-611": VulnType.XXE,
    "CWE-79": VulnType.XSS,
    "CWE-502": VulnType.DESERIALIZATION,
    "CWE-22": VulnType.PATH_TRAVERSAL,
    "CWE-23": VulnType.PATH_TRAVERSAL,
    "CWE-35": VulnType.PATH_TRAVERSAL,
    "CWE-639": VulnType.IDOR,
    "CWE-287": VulnType.AUTH_BYPASS,
    "CWE-306": VulnType.AUTH_BYPASS,
    "CWE-269": VulnType.PRIVILEGE_ESCALATION,
    "CWE-521": VulnType.WEAK_CREDENTIALS,
}


def vuln_type_for_cwe(cwe: str) -> VulnType | None:
    """Return the VulnType for a single CWE, or None if not oracle-verifiable."""
    return _CWE_TO_VULN.get(cwe)


def vuln_type_for_cwes(cwes: Sequence[str]) -> VulnType | None:
    """First mappable VulnType across a finding's CWEs, or None."""
    for cwe in cwes:
        vt = vuln_type_for_cwe(cwe)
        if vt is not None:
            return vt
    return None
