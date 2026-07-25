"""TDD tests for PtaiAdapter (M2 Task 2, ADR-014: adopt pentest-ai).

pentest-ai is not installed in this environment, so the adapter is tested with
an injected fake ``ptai`` module that stands in for the real API. The adapter's
job is to translate a single pentest-ai reproduction into the ReproductionStatus
the OracleEngine consumes.
"""
from __future__ import annotations

from typing import Any

from secopent.application.oracle import OracleVerifier
from secopent.domain.verification.models import (
    CandidateFinding,
    ReproductionStatus,
    VerificationMethod,
    VulnType,
)
from secopent.infrastructure.oracle.ptai_adapter import PtaiAdapter


class FakePtai:
    """Records calls and returns a canned status string."""

    def __init__(self, status: str) -> None:
        self._status = status
        self.calls: list[dict[str, Any]] = []

    def verify(self, *, target: str, vuln_type: str, canary_token: str, n: int) -> str:
        self.calls.append(
            {"target": target, "vuln_type": vuln_type, "canary_token": canary_token, "n": n}
        )
        return self._status


def _candidate() -> CandidateFinding:
    return CandidateFinding(
        id="cand-1", observation_id="obs-1", vuln_type=VulnType.RCE, target="https://x.test/"
    )


def _method() -> VerificationMethod:
    return VerificationMethod(vuln_type=VulnType.RCE, default_n=3)


def test_maps_success() -> None:
    adapter = PtaiAdapter(FakePtai("success"))
    status = adapter.reproduce(_candidate(), _method(), canary_token="tok")
    assert status is ReproductionStatus.SUCCESS


def test_maps_failure() -> None:
    adapter = PtaiAdapter(FakePtai("failure"))
    status = adapter.reproduce(_candidate(), _method(), canary_token="tok")
    assert status is ReproductionStatus.FAILURE


def test_maps_server_error() -> None:
    adapter = PtaiAdapter(FakePtai("server_error"))
    assert (
        adapter.reproduce(_candidate(), _method(), canary_token="tok")
        is ReproductionStatus.SERVER_ERROR
    )


def test_forwards_target_vuln_type_and_canary_to_ptai() -> None:
    fake = FakePtai("success")
    adapter = PtaiAdapter(fake)
    adapter.reproduce(_candidate(), _method(), canary_token="canary-123")
    call = fake.calls[0]
    assert call["target"] == "https://x.test/"
    assert call["vuln_type"] == "rce"
    assert call["canary_token"] == "canary-123"


def test_adapter_satisfies_oracle_verifier_protocol() -> None:
    assert isinstance(PtaiAdapter(FakePtai("success")), OracleVerifier)
