"""vulhub ground-truth regression (CVE-reproduction class, M2 Task 5).

vulhub reproduces real CVEs in containers. A known-vulnerable environment must
CONFIRM at N/N; the patched environment must REFUTE - this is the regression that
guards the oracle against false positives/negatives as it evolves. Simulated via
GroundTruthVerifier until the real docker-compose range lands in M5.
"""
from __future__ import annotations

from secopent.domain.verification.models import VerificationStatus, VulnType


def test_vulhub_rce_cve_confirms_on_vulnerable(make_oracle, make_candidate) -> None:  # type: ignore[no-untyped-def]
    engine, _ = make_oracle(vuln_present=True)
    result = engine.verify(
        make_candidate(VulnType.RCE, "https://vulhub.test/cve/"), actor="oracle"
    )
    assert result.status is VerificationStatus.CONFIRMED
    assert result.successes == 3  # RCE N=3


def test_vulhub_deserialization_confirms_on_vulnerable(make_oracle, make_candidate) -> None:  # type: ignore[no-untyped-def]
    engine, _ = make_oracle(vuln_present=True)
    result = engine.verify(
        make_candidate(VulnType.DESERIALIZATION, "https://vulhub.test/cve/"), actor="oracle"
    )
    assert result.status is VerificationStatus.CONFIRMED


def test_vulhub_patched_environment_refutes(make_oracle, make_candidate) -> None:  # type: ignore[no-untyped-def]
    engine, _ = make_oracle(vuln_present=False)
    result = engine.verify(
        make_candidate(VulnType.RCE, "https://vulhub.test/cve/"), actor="oracle"
    )
    assert result.status is VerificationStatus.REFUTED
