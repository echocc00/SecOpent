"""TDD tests for the verification domain (M2 Task 1, §9 / ADR-004).

The verification domain carries the curated knowledge of *how to verify* each
vulnerability type: how many independent reproductions (N) are required for an
N/N confirmation, the retry strategy, the 5xx (server-error) threshold that
turns a failed verification into INCONCLUSIVE (escalate to human) rather than
REFUTED, and the OOB callback window for out-of-band methods.

The N/N decision is a deterministic domain rule (``decide_outcome``) - the LLM
never marks a finding Confirmed; only the oracle does, via this rule (LLM边界).
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from secopent.domain.common.errors import DomainValidationError
from secopent.domain.verification.models import (
    CandidateFinding,
    ConfirmedFinding,
    RetryStrategy,
    VerificationMethod,
    VerificationResult,
    VerificationStatus,
    VulnType,
    decide_outcome,
)
from secopent.domain.verification.registry import (
    VerificationMethodRegistry,
    default_registry,
)


def test_vuln_type_has_fourteen_curated_classes() -> None:
    assert len(list(VulnType)) == 14


def test_method_defaults_to_cross_worker_and_threshold_two() -> None:
    method = VerificationMethod(vuln_type=VulnType.XSS, default_n=3)
    assert method.retry_strategy is RetryStrategy.CROSS_WORKER
    assert method.cross_worker is True
    assert method.server_error_threshold == 2
    assert method.oob_window_seconds == 0


def test_method_rejects_non_positive_n() -> None:
    with pytest.raises(DomainValidationError):
        VerificationMethod(vuln_type=VulnType.XSS, default_n=0)


def test_method_rejects_non_positive_threshold() -> None:
    with pytest.raises(DomainValidationError):
        VerificationMethod(
            vuln_type=VulnType.XSS, default_n=3, server_error_threshold=0
        )


def test_method_rejects_negative_oob_window() -> None:
    with pytest.raises(DomainValidationError):
        VerificationMethod(vuln_type=VulnType.SSRF, default_n=3, oob_window_seconds=-1)


def test_default_registry_covers_all_fourteen_vuln_types() -> None:
    registry = default_registry()
    for vuln_type in VulnType:
        assert registry.method_for(vuln_type) is not None, vuln_type


def test_sqli_uses_higher_n_for_timing() -> None:
    # SQLi timing-based verification needs more independent reproductions.
    assert default_registry().method_for(VulnType.SQLI).default_n == 5


def test_rce_echo_uses_n_three() -> None:
    assert default_registry().method_for(VulnType.RCE).default_n == 3


def test_oob_methods_carry_a_positive_window() -> None:
    registry = default_registry()
    for vuln_type in (VulnType.SSRF, VulnType.XXE, VulnType.DESERIALIZATION):
        method = registry.method_for(vuln_type)
        assert method.oob_window_seconds > 0, vuln_type


def test_method_for_unknown_returns_none() -> None:
    registry = VerificationMethodRegistry(
        [VerificationMethod(vuln_type=VulnType.XSS, default_n=3)]
    )
    assert registry.method_for(VulnType.SQLI) is None


def test_require_method_unknown_raises() -> None:
    registry = VerificationMethodRegistry([])
    with pytest.raises(DomainValidationError):
        registry.require_method(VulnType.SQLI)


def test_registry_rejects_duplicate_vuln_type() -> None:
    with pytest.raises(DomainValidationError):
        VerificationMethodRegistry(
            [
                VerificationMethod(vuln_type=VulnType.XSS, default_n=3),
                VerificationMethod(vuln_type=VulnType.XSS, default_n=5),
            ]
        )


def test_registry_vuln_types_sorted() -> None:
    registry = default_registry()
    types = registry.vuln_types()
    assert len(types) == 14
    assert types == tuple(sorted(types))


def test_candidate_finding_defaults_to_pending() -> None:
    candidate = CandidateFinding(
        id="cand-1", observation_id="obs-1", vuln_type=VulnType.SQLI, target="https://x.test/"
    )
    assert candidate.status is VerificationStatus.PENDING


def test_confirmed_finding_carries_evidence_and_timestamp() -> None:
    verified_at = datetime(2026, 1, 1, tzinfo=UTC)
    confirmed = ConfirmedFinding(
        candidate_id="cand-1",
        vuln_type=VulnType.SQLI,
        evidence_ids=("ev-1", "ev-2"),
        verified_at=verified_at,
        successes=5,
        attempts=5,
    )
    assert confirmed.evidence_ids == ("ev-1", "ev-2")
    assert confirmed.verified_at == verified_at


def test_verification_result_requires_consistent_counts() -> None:
    with pytest.raises(DomainValidationError):
        VerificationResult(status=VerificationStatus.CONFIRMED, successes=5, attempts=3)


# ---------------------------------------------------------------------------
# decide_outcome: the deterministic N/N rule
# ---------------------------------------------------------------------------


def test_decide_confirmed_when_n_successes_reached() -> None:
    method = VerificationMethod(vuln_type=VulnType.RCE, default_n=3)
    assert decide_outcome(method, successes=3, attempts=3) is VerificationStatus.CONFIRMED
    # More successes than N is still confirmed.
    assert decide_outcome(method, successes=4, attempts=5) is VerificationStatus.CONFIRMED


def test_decide_refuted_when_attempts_exhausted_without_n() -> None:
    method = VerificationMethod(vuln_type=VulnType.RCE, default_n=3)
    # 3 attempts, only 1 success, no server errors -> REFUTED (not INCONCLUSIVE).
    assert (
        decide_outcome(method, successes=1, attempts=3, inconclusive_count=0)
        is VerificationStatus.REFUTED
    )


def test_decide_inconclusive_when_server_errors_breach_threshold() -> None:
    method = VerificationMethod(
        vuln_type=VulnType.RCE, default_n=3, server_error_threshold=2
    )
    # Attempts exhausted, 2 server-error inconclusives (>= threshold) -> escalate.
    assert (
        decide_outcome(method, successes=1, attempts=3, inconclusive_count=2)
        is VerificationStatus.INCONCLUSIVE
    )


def test_decide_pending_when_not_enough_attempts() -> None:
    method = VerificationMethod(vuln_type=VulnType.SQLI, default_n=5)
    # Only 2 attempts so far, 1 success -> not yet decided.
    assert (
        decide_outcome(method, successes=1, attempts=2) is VerificationStatus.PENDING
    )
