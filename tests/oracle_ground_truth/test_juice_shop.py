"""Juice Shop ground-truth regression (Web-application class, M2 Task 5).

Juice Shop is the canonical vulnerable web app. Known-present vulns must CONFIRM
at N/N; the same probes against a clean target must REFUTE. Simulated via
GroundTruthVerifier until the real docker-compose range lands in M5.
"""
from __future__ import annotations

from secopent.domain.verification.models import VerificationStatus, VulnType


def test_juice_shop_sqli_confirms_when_present(make_oracle, make_candidate) -> None:  # type: ignore[no-untyped-def]
    engine, _ = make_oracle(vuln_present=True)
    result = engine.verify(make_candidate(VulnType.SQLI), actor="oracle")
    assert result.status is VerificationStatus.CONFIRMED
    assert result.successes == 5  # SQLi N=5


def test_juice_shop_xss_confirms_when_present(make_oracle, make_candidate) -> None:  # type: ignore[no-untyped-def]
    engine, _ = make_oracle(vuln_present=True)
    result = engine.verify(make_candidate(VulnType.XSS), actor="oracle")
    assert result.status is VerificationStatus.CONFIRMED


def test_juice_shop_clean_target_refutes(make_oracle, make_candidate) -> None:  # type: ignore[no-untyped-def]
    engine, _ = make_oracle(vuln_present=False)
    result = engine.verify(make_candidate(VulnType.SQLI), actor="oracle")
    assert result.status is VerificationStatus.REFUTED
    assert result.successes == 0
