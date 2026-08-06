"""Echo canary per-method gate: factory embedding + engine behavior.

v0.5.0 Phase 3 (3.1, errata E1/E2). The echo canary rides inside the probe
URL (so it actually reaches the target) and is embedded ONLY for echo-enabled
methods (XSS). These tests prove:
- the factory embeds ``echo={{canary_token}}`` for XSS and never for
  non-echo methods; the OOB placeholder stays always-on (no regression);
- a reflecting target confirms XSS through the echo branch (N/N);
- a non-reflecting target REFUTES XSS (strict semantics - no legacy fallback);
- non-echo methods (SQLi) are untouched by the gate (legacy path).
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from secopent.application.canary import CANARY_PLACEHOLDER, CanaryTokenManager
from secopent.application.oracle import OracleEngine
from secopent.domain.adapters.contracts import (
    AdapterSource,
    CoverageDomain,
    Observation,
    Severity,
)
from secopent.domain.verification.models import (
    CandidateFinding,
    VerificationStatus,
    VulnType,
)
from secopent.domain.verification.registry import default_registry
from secopent.infrastructure.oracle.rescan_verifier import OOB_PLACEHOLDER
from secopent.infrastructure.oracle.verifier_factory import RescanVerifierFactory


class _FindingStub:
    def __init__(self, asset: str) -> None:
        self.asset = asset


class _Result:
    observations: tuple[Any, ...] = ()
    stdout: str = ""


class _ReflectingRunner:
    """Echoes the scan args into stdout - a target that reflects the probe."""

    def __init__(self, *, reflect: bool) -> None:
        self._reflect = reflect

    def scan(self, adapter_key: str, *, args: Sequence[str], **kwargs: object) -> _Result:
        r = _Result()
        r.observations = ()
        r.stdout = " ".join(args) if self._reflect else "no canary here"
        return r


class _ObservationRunner:
    """Returns one observation matching the asset (legacy-path SUCCESS)."""

    def __init__(self, asset: str) -> None:
        self._asset = asset

    def scan(self, adapter_key: str, *, args: Sequence[str], **kwargs: object) -> _Result:
        r = _Result()
        r.stdout = ""
        r.observations = (
            Observation(
                external_id="o1", asset_identity=self._asset,
                source=AdapterSource(name="nuclei", version="1", template_version="1"),
                rule_id="sqli", rule_version="1",
                coverage_domain=CoverageDomain.WEB, title="SQLi",
                severity=Severity.HIGH, confidence=0.9,
            ),
        )
        return r


class _NoopAudit:
    def record(self, **kwargs: object) -> None:
        return None


def _probe_url(verifier: Any) -> str:
    args = verifier._scan_kwargs["args"]
    return str(args[args.index("-u") + 1])


def test_factory_embeds_echo_placeholder_for_xss() -> None:
    factory = RescanVerifierFactory(
        _ReflectingRunner(reflect=True), None, None,  # type: ignore[arg-type]
        method_registry=default_registry(),
    )
    verifier = factory.for_finding(_FindingStub("https://x.test/"), VulnType.XSS)
    url = _probe_url(verifier)
    assert f"echo={CANARY_PLACEHOLDER}" in url
    assert OOB_PLACEHOLDER in url  # OOB embedding not regressed


def test_factory_omits_echo_placeholder_for_non_echo_methods() -> None:
    factory = RescanVerifierFactory(
        _ReflectingRunner(reflect=True), None, None,  # type: ignore[arg-type]
        method_registry=default_registry(),
    )
    for vuln_type in (VulnType.SQLI, VulnType.RCE, VulnType.SSRF):
        verifier = factory.for_finding(_FindingStub("https://x.test/"), vuln_type)
        url = _probe_url(verifier)
        assert CANARY_PLACEHOLDER not in url, vuln_type
        assert OOB_PLACEHOLDER in url  # always-on OOB placeholder kept


def test_factory_without_registry_keeps_legacy_shape() -> None:
    """Backward compat: no registry wired -> no echo embedding at all."""
    factory = RescanVerifierFactory(_ReflectingRunner(reflect=True), None, None)  # type: ignore[arg-type]
    verifier = factory.for_finding(_FindingStub("https://x.test/"), VulnType.XSS)
    assert CANARY_PLACEHOLDER not in _probe_url(verifier)


def _engine(runner: Any, vuln_type: VulnType) -> OracleEngine:
    registry = default_registry()
    canary = CanaryTokenManager(_NoopAudit())  # type: ignore[arg-type]
    factory = RescanVerifierFactory(
        runner, None, canary, method_registry=registry
    )
    verifier = factory.for_finding(_FindingStub("https://x.test/"), vuln_type)
    return OracleEngine(registry=registry, verifier=verifier, canary=canary)


def _candidate(vuln_type: VulnType) -> CandidateFinding:
    return CandidateFinding(
        id="c1", observation_id="o1", vuln_type=vuln_type, target="https://x.test/"
    )


def test_xss_confirms_when_target_reflects_canary() -> None:
    engine = _engine(_ReflectingRunner(reflect=True), VulnType.XSS)
    result = engine.verify(_candidate(VulnType.XSS), actor="oracle")
    assert result.status is VerificationStatus.CONFIRMED
    assert result.successes == result.attempts  # N/N echoes


def test_xss_refuted_without_reflection_strict_semantics() -> None:
    """E2: strict echo - no reflection means REFUTED, no legacy fallback.

    The runner returns no observations either, so a legacy path could not
    have produced a confirmation regardless - the echo branch is the only
    game in town for echo-enabled methods.
    """
    engine = _engine(_ReflectingRunner(reflect=False), VulnType.XSS)
    result = engine.verify(_candidate(VulnType.XSS), actor="oracle")
    assert result.status is VerificationStatus.REFUTED
    assert result.successes == 0


def test_sqli_legacy_path_untouched_by_gate() -> None:
    """Non-echo method: no echo placeholder -> legacy observation match."""
    engine = _engine(_ObservationRunner("https://x.test/"), VulnType.SQLI)
    result = engine.verify(_candidate(VulnType.SQLI), actor="oracle")
    assert result.status is VerificationStatus.CONFIRMED
    assert result.successes == 5  # SQLi N=5
