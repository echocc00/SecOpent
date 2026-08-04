"""RescanVerifier OOB canary path (W3-E T2)."""
from __future__ import annotations

from typing import Any

from secopent.domain.verification.models import (
    CandidateFinding,
    ReproductionStatus,
    VerificationMethod,
    VulnType,
)
from secopent.infrastructure.oracle.interactsh import InteractshClient
from secopent.infrastructure.oracle.rescan_verifier import OOB_PLACEHOLDER, RescanVerifier


class _FakeTransport:
    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records = records

    def register(self) -> str:
        return "oast.example.com"

    def poll(self, correlation_domain: str) -> list[dict[str, Any]]:
        return list(self._records)


class _FakeRunner:
    def __init__(self) -> None:
        self.calls = 0

    def scan(self, adapter_key: str, *, args: Any, **kwargs: Any) -> Any:
        self.calls += 1

        class _R:
            observations = ()
            stdout = ""

        return _R()


def _candidate() -> CandidateFinding:
    return CandidateFinding(
        id="c-1", observation_id="o-1", vuln_type=VulnType.SSRF, target="http://t/"
    )


def _oob_method() -> VerificationMethod:
    return VerificationMethod(
        vuln_type=VulnType.SSRF,
        default_n=1,
        oob_window_seconds=30,
    )


def _kwargs_with_placeholder() -> dict[str, Any]:
    return {
        "adapter_key": "nuclei",
        "args": ["-u", f"http://t/?cb={OOB_PLACEHOLDER}"],
    }


def test_oob_callback_present_yields_success() -> None:
    records = [{"unique_id": "tok-1", "protocol": "dns", "raw": "x"}]
    interactsh = InteractshClient(_FakeTransport(records))
    runner = _FakeRunner()
    verifier = RescanVerifier(
        runner,  # type: ignore[arg-type]
        _kwargs_with_placeholder(),
        canary=None,
        interactsh=interactsh,
        oob_sleep=lambda _s: None,
    )
    status = verifier.reproduce(_candidate(), _oob_method(), canary_token="tok-1")
    assert status is ReproductionStatus.SUCCESS
    assert runner.calls == 1  # scan ran once


def test_oob_callback_absent_yields_failure() -> None:
    interactsh = InteractshClient(_FakeTransport([]))  # no records
    verifier = RescanVerifier(
        _FakeRunner(),  # type: ignore[arg-type]
        _kwargs_with_placeholder(),
        canary=None,
        interactsh=interactsh,
        oob_sleep=lambda _s: None,
    )
    status = verifier.reproduce(_candidate(), _oob_method(), canary_token="tok-2")
    assert status is ReproductionStatus.FAILURE


def test_oob_path_skipped_when_no_placeholder() -> None:
    """Without the OOB placeholder, falls back to legacy (no interactsh use)."""
    records = [{"unique_id": "tok-3", "protocol": "dns", "raw": "x"}]
    interactsh = InteractshClient(_FakeTransport(records))
    kwargs = {"adapter_key": "nuclei", "args": ["-u", "http://t/"]}  # no placeholder
    verifier = RescanVerifier(
        _FakeRunner(),  # type: ignore[arg-type]
        kwargs,
        canary=None,
        interactsh=interactsh,
        oob_sleep=lambda _s: None,
    )
    # Legacy path: no observations -> FAILURE (OOB callback ignored).
    status = verifier.reproduce(_candidate(), _oob_method(), canary_token="tok-3")
    assert status is ReproductionStatus.FAILURE


def test_oob_path_skipped_when_window_zero() -> None:
    """method.oob_window_seconds=0 -> not OOB, legacy path even with placeholder."""
    records = [{"unique_id": "tok-4", "protocol": "dns", "raw": "x"}]
    interactsh = InteractshClient(_FakeTransport(records))
    method = VerificationMethod(vuln_type=VulnType.SQLI, default_n=1, oob_window_seconds=0)
    verifier = RescanVerifier(
        _FakeRunner(),  # type: ignore[arg-type]
        _kwargs_with_placeholder(),
        canary=None,
        interactsh=interactsh,
        oob_sleep=lambda _s: None,
    )
    status = verifier.reproduce(_candidate(), method, canary_token="tok-4")
    assert status is ReproductionStatus.FAILURE  # legacy path, no obs


def test_oob_path_skipped_when_no_interactsh() -> None:
    """No interactsh wired -> legacy path even with placeholder + window>0."""
    verifier = RescanVerifier(
        _FakeRunner(),  # type: ignore[arg-type]
        _kwargs_with_placeholder(),
        canary=None,
        interactsh=None,
        oob_sleep=lambda _s: None,
    )
    status = verifier.reproduce(_candidate(), _oob_method(), canary_token="tok-5")
    assert status is ReproductionStatus.FAILURE  # legacy path, no obs
