# tests/infrastructure/test_rescan_verifier_canary.py
"""RescanVerifier canary token wiring (W2-C T4).

When the scan kwargs contain the {{canary_token}} placeholder and a
CanaryTokenManager is injected, reproduce embeds the token, runs the scan,
and requires the token to echo back in stdout (else NOT confirmed). Without
a placeholder the legacy substring match is used (backward compat).
"""
from __future__ import annotations

from typing import Any

from secopent.application.canary import CANARY_PLACEHOLDER, CanaryTokenManager
from secopent.domain.adapters.contracts import (
    AdapterSource,
    CoverageDomain,
    Observation,
    Severity,
)
from secopent.domain.verification.models import (
    CandidateFinding,
    ReproductionStatus,
    VerificationMethod,
    VulnType,
)
from secopent.infrastructure.oracle.rescan_verifier import RescanVerifier


class _NullAudit:
    def record(self, **kwargs: Any) -> None:
        return None


class _FakeRunner:
    """Returns a canned RealScanResult; captures the args it was called with."""

    def __init__(self, *, stdout: str, asset_identity: str = "http://target") -> None:
        self._stdout = stdout
        self._asset_identity = asset_identity
        self.captured_args: list[str] | None = None

    def scan(self, adapter_key: str, *, args: list[str], **kwargs: Any) -> Any:
        self.captured_args = list(args)
        observations = (
            Observation(
                external_id="o1", asset_identity=self._asset_identity,
                source=AdapterSource(name="nuclei", version="1", template_version="1"),
                rule_id="r", rule_version="1", coverage_domain=CoverageDomain.WEB,
                title="t", severity=Severity.HIGH, confidence=0.9,
            ),
        )

        class _Result:
            pass

        r = _Result()
        r.observations = observations  # type: ignore[attr-defined]
        r.stdout = self._stdout  # type: ignore[attr-defined]
        return r  # type: ignore[return-value]


def _candidate() -> CandidateFinding:
    return CandidateFinding(
        id="c1", observation_id="o1", vuln_type=VulnType.SQLI, target="http://target",
    )


def _method() -> VerificationMethod:
    return VerificationMethod(vuln_type=VulnType.SQLI, default_n=1)


def test_canary_token_embedded_into_scan_args() -> None:
    canary = CanaryTokenManager(_NullAudit())
    token = canary.generate(actor="test", candidate_id="c1")
    runner = _FakeRunner(stdout="echo-" + token)
    verifier = RescanVerifier(
        runner=runner,  # type: ignore[arg-type]
        scan_kwargs={"adapter_key": "nuclei", "args": ["-u", f"http://t/{CANARY_PLACEHOLDER}"]},
        canary=canary,
    )
    verifier.reproduce(_candidate(), _method(), canary_token=token)

    assert runner.captured_args is not None
    assert CANARY_PLACEHOLDER not in runner.captured_args[1]
    assert token in runner.captured_args[1]  # placeholder replaced with the token


def test_canary_echo_confirms() -> None:
    canary = CanaryTokenManager(_NullAudit())
    token = canary.generate(actor="test", candidate_id="c1")
    runner = _FakeRunner(stdout=f"response contains {token} here")
    verifier = RescanVerifier(
        runner=runner,  # type: ignore[arg-type]
        scan_kwargs={"adapter_key": "nuclei", "args": [CANARY_PLACEHOLDER]},
        canary=canary,
    )
    status = verifier.reproduce(_candidate(), _method(), canary_token=token)
    assert status is ReproductionStatus.SUCCESS


def test_canary_not_echoed_is_not_confirmed() -> None:
    """No echo in stdout -> FAILURE (not SUCCESS), even if the target string
    appears in observations (canary is the stronger signal)."""
    canary = CanaryTokenManager(_NullAudit())
    token = canary.generate(actor="test", candidate_id="c1")
    runner = _FakeRunner(stdout="no canary here", asset_identity="http://target")
    verifier = RescanVerifier(
        runner=runner,  # type: ignore[arg-type]
        scan_kwargs={"adapter_key": "nuclei", "args": [CANARY_PLACEHOLDER]},
        canary=canary,
    )
    status = verifier.reproduce(_candidate(), _method(), canary_token=token)
    assert status is not ReproductionStatus.SUCCESS


def test_no_placeholder_falls_back_to_substring_match() -> None:
    """Without {{canary_token}} in the kwargs, the legacy substring check runs."""
    canary = CanaryTokenManager(_NullAudit())
    token = canary.generate(actor="test", candidate_id="c1")
    runner = _FakeRunner(stdout="irrelevant", asset_identity="http://target")
    verifier = RescanVerifier(
        runner=runner,  # type: ignore[arg-type]
        scan_kwargs={"adapter_key": "nuclei", "args": ["-u", "http://target"]},
        canary=canary,
    )
    status = verifier.reproduce(_candidate(), _method(), canary_token=token)
    assert status is ReproductionStatus.SUCCESS  # target matched in observations
