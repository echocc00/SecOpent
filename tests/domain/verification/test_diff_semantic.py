# tests/domain/verification/test_diff_semantic.py
"""Domain tests for DIFF_SEMANTIC confirmation (spec §5, Task 1)."""
from __future__ import annotations

import pytest

from secopent.domain.common.errors import DomainValidationError
from secopent.domain.verification.diff_semantic import DiffSemanticPayload, Expectation
from secopent.domain.verification.models import (
    CandidateFinding,
    VerificationMethod,
    VulnType,
)


def _payload() -> DiffSemanticPayload:
    return DiffSemanticPayload(
        candidate_id="c1",
        baseline_request={"method": "GET", "url": "/api/orders/1001", "session": "userA"},
        assertion_request={"method": "GET", "url": "/api/orders/1002", "session": "userA"},
        expectation=Expectation.DENY,
        state_readback="/api/balance",
    )


class TestVerificationMethod:
    def test_diff_semantic_default_false(self) -> None:
        m = VerificationMethod(vuln_type=VulnType.IDOR, default_n=3)
        assert m.diff_semantic is False

    def test_diff_semantic_true(self) -> None:
        m = VerificationMethod(vuln_type=VulnType.IDOR, default_n=3, diff_semantic=True)
        assert m.diff_semantic is True

    def test_echo_and_diff_mutually_exclusive(self) -> None:
        with pytest.raises(DomainValidationError):
            VerificationMethod(
                vuln_type=VulnType.IDOR,
                default_n=3,
                echo_enabled=True,
                diff_semantic=True,
            )


class TestDiffSemanticPayload:
    def test_frozen_valid(self) -> None:
        p = _payload()
        assert p.expectation is Expectation.DENY
        assert p.state_readback == "/api/balance"

    def test_requires_non_empty_baseline_request(self) -> None:
        with pytest.raises(DomainValidationError):
            DiffSemanticPayload(
                candidate_id="c1",
                baseline_request={},
                assertion_request={"method": "GET", "url": "/b"},
                expectation=Expectation.DENY,
            )

    def test_requires_non_empty_assertion_request(self) -> None:
        with pytest.raises(DomainValidationError):
            DiffSemanticPayload(
                candidate_id="c1",
                baseline_request={"method": "GET", "url": "/a"},
                assertion_request={},
                expectation=Expectation.DENY,
            )

    def test_requires_candidate_id(self) -> None:
        with pytest.raises(DomainValidationError):
            DiffSemanticPayload(
                candidate_id="",
                baseline_request={},
                assertion_request={},
                expectation=Expectation.DENY,
            )


class TestCandidateFindingDiff:
    def test_candidate_carries_diff(self) -> None:
        c = CandidateFinding(
            id="c1",
            observation_id="o1",
            vuln_type=VulnType.IDOR,
            target="https://x",
            diff=_payload(),
        )
        assert c.diff is not None

    def test_candidate_without_diff_default_none(self) -> None:
        c = CandidateFinding(
            id="c1",
            observation_id="o1",
            vuln_type=VulnType.IDOR,
            target="https://x",
        )
        assert c.diff is None
