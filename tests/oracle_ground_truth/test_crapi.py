"""crAPI ground-truth regression (API class, M2 Task 5).

crAPI (completely ridiculous API) is the canonical vulnerable API. IDOR/BOLA and
auth-bypass are its signature flaws: present -> CONFIRM at N/N, absent -> REFUTE.
Simulated via GroundTruthVerifier until the real range lands in M5.
"""
from __future__ import annotations

from secopent.domain.verification.models import VerificationStatus, VulnType


def test_crapi_idor_confirms_when_present(make_oracle, make_candidate) -> None:  # type: ignore[no-untyped-def]
    engine, _ = make_oracle(vuln_present=True)
    result = engine.verify(
        make_candidate(VulnType.IDOR, "https://api.crapi.test/"), actor="oracle"
    )
    assert result.status is VerificationStatus.CONFIRMED
    assert result.successes == 3  # IDOR N=3


def test_crapi_auth_bypass_confirms_when_present(make_oracle, make_candidate) -> None:  # type: ignore[no-untyped-def]
    engine, _ = make_oracle(vuln_present=True)
    result = engine.verify(
        make_candidate(VulnType.AUTH_BYPASS, "https://api.crapi.test/"), actor="oracle"
    )
    assert result.status is VerificationStatus.CONFIRMED


def test_crapi_hardened_endpoint_refutes(make_oracle, make_candidate) -> None:  # type: ignore[no-untyped-def]
    engine, _ = make_oracle(vuln_present=False)
    result = engine.verify(
        make_candidate(VulnType.IDOR, "https://api.crapi.test/"), actor="oracle"
    )
    assert result.status is VerificationStatus.REFUTED
