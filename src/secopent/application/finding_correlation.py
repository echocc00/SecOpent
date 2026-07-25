# src/secopent/application/finding_correlation.py
"""FindingCorrelation: deterministic cross-tool de-duplication (§13).

Groups Observations by their deterministic fingerprint (asset + CWE + CVE) and
merges each group into one Finding: unioned CWE/CVE/OWASP attribution, all
correlated observation ids, and the maximum severity. Because the fingerprint
excludes the reporting source, the same vulnerability found by multiple tools
collapses to a single reportable Finding. No LLM judgment is involved.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..domain.adapters.contracts import Observation, Severity
from ..domain.findings.fingerprint import observation_fingerprint
from ..domain.findings.models import Finding, FindingStatus

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _max_severity(observations: list[Observation]) -> Severity:
    return max(observations, key=lambda o: _SEVERITY_RANK[o.severity]).severity


class FindingCorrelation:
    """Correlate Observations into de-duplicated Findings."""

    def correlate(self, observations: Iterable[Observation]) -> tuple[Finding, ...]:
        """Group observations by fingerprint and merge each group into a Finding."""
        groups: dict[str, list[Observation]] = {}
        for observation in observations:
            groups.setdefault(observation_fingerprint(observation), []).append(observation)

        findings: list[Finding] = []
        for fingerprint, group in groups.items():
            first = group[0]
            cwe = sorted({c for o in group for c in o.cwe})
            cve = sorted({c for o in group for c in o.cve})
            owasp = sorted({c for o in group for c in o.owasp})
            findings.append(
                Finding(
                    id=f"finding:{fingerprint.removeprefix('sha256:')[:16]}",
                    fingerprint=fingerprint,
                    title=first.title,
                    asset=first.asset_identity,
                    severity=_max_severity(group),
                    cwe=tuple(cwe),
                    cve=tuple(cve),
                    owasp=tuple(owasp),
                    observation_ids=tuple(o.external_id for o in group),
                    status=FindingStatus.CANDIDATE,
                )
            )
        return tuple(findings)
