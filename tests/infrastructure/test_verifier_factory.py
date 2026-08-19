"""RescanVerifierFactory embeds OOB canary placeholder (W4-C T2).

The OOB branch in RescanVerifier.reproduce fires only when ``scan_kwargs``
carries ``{{canary_oob_subdomain}}`` (W3-E). The factory builds production
scan_kwargs, so it must embed the placeholder for OOB verification to be
active when a real Interactsh transport is configured. Only the OOB
placeholder is embedded: the echo (``{{canary_token}}``) path has no per-method
gate, so embedding it blanketly would switch every non-OOB finding from legacy
substring match to stricter echo verification and regress non-reflection
findings. Echo embedding is deferred until a per-method echo gate exists.
"""
from __future__ import annotations

from types import SimpleNamespace

from secopent.domain.verification.registry import VerificationMethodRegistry
from secopent.infrastructure.oracle.rescan_verifier import OOB_PLACEHOLDER
from secopent.infrastructure.oracle.verifier_factory import RescanVerifierFactory


class _FakeRunner:
    def scan(self, **_kwargs: object) -> object:  # noqa: ARG002
        return None


class _FakeCanary:  # opaque - the factory only stores it
    pass


def _factory() -> RescanVerifierFactory:
    return RescanVerifierFactory(_FakeRunner(), None, _FakeCanary())


def _u_value(verifier: object) -> str:
    args = verifier._scan_kwargs["args"]  # type: ignore[attr-defined]
    return args[args.index("-u") + 1]


def test_factory_embeds_oob_placeholder_in_url() -> None:
    verifier = _factory().for_finding(SimpleNamespace(asset="http://t:3000/path"))
    assert OOB_PLACEHOLDER in _u_value(verifier)


def test_appends_query_separator_when_no_existing_query() -> None:
    verifier = _factory().for_finding(SimpleNamespace(asset="http://t:3000/path"))
    assert f"?cb={OOB_PLACEHOLDER}" in _u_value(verifier)


def test_uses_ampersand_when_query_already_exists() -> None:
    verifier = _factory().for_finding(SimpleNamespace(asset="http://t:3000/p?x=1"))
    assert f"?x=1&cb={OOB_PLACEHOLDER}" in _u_value(verifier)


# --- DIFF_SEMANTIC dispatch (v0.7.6, Task 5) -------------------------------


class _FakeDiffRunner:
    """Scripted diff runner produced by the injected diff_runner_factory (no
    real httpx client is constructed in tests)."""

    def execute(self, request: object) -> object:  # noqa: ARG002
        return None

    def with_session(self, session: object) -> _FakeDiffRunner:
        return self


def _managed_registry() -> VerificationMethodRegistry:
    from secopent.domain.verification.registry import default_registry

    return default_registry()


def _idor_finding() -> SimpleNamespace:
    return SimpleNamespace(asset="http://t:3000/idor", vuln_type="idor")


def test_factory_returns_diff_semantic_verifier_for_idor() -> None:
    from secopent.domain.verification.models import VulnType
    from secopent.infrastructure.oracle.diff_semantic_verifier import (
        DiffSemanticVerifier,
    )
    from secopent.infrastructure.oracle.rescan_verifier import RescanVerifier

    factory = RescanVerifierFactory(
        _FakeRunner(),
        None,
        _FakeCanary(),
        method_registry=_managed_registry(),
        diff_runner_factory=lambda: _FakeDiffRunner(),
    )
    verifier = factory.for_finding(_idor_finding(), vuln_type=VulnType.IDOR)
    assert isinstance(verifier, DiffSemanticVerifier)
    assert not isinstance(verifier, RescanVerifier)


def test_factory_derives_vuln_type_from_finding() -> None:
    """When vuln_type is not passed, the factory derives it from finding.vuln_type."""
    from secopent.domain.verification.models import VulnType
    from secopent.infrastructure.oracle.diff_semantic_verifier import (
        DiffSemanticVerifier,
    )

    finding = SimpleNamespace(asset="http://t:3000/idor", vuln_type=VulnType.IDOR)
    factory = RescanVerifierFactory(
        _FakeRunner(),
        None,
        _FakeCanary(),
        method_registry=_managed_registry(),
        diff_runner_factory=lambda: _FakeDiffRunner(),
    )
    verifier = factory.for_finding(finding)
    assert isinstance(verifier, DiffSemanticVerifier)


def test_factory_xss_still_returns_rescan_verifier() -> None:
    """Echo path (XSS) is unaffected by diff dispatch."""
    from secopent.domain.verification.models import VulnType
    from secopent.infrastructure.oracle.diff_semantic_verifier import (
        DiffSemanticVerifier,
    )
    from secopent.infrastructure.oracle.rescan_verifier import RescanVerifier

    factory = RescanVerifierFactory(
        _FakeRunner(),
        None,
        _FakeCanary(),
        method_registry=_managed_registry(),
        diff_runner_factory=lambda: _FakeDiffRunner(),
    )
    finding = SimpleNamespace(asset="http://t:3000/x?q=1", vuln_type=VulnType.XSS)
    verifier = factory.for_finding(finding, vuln_type=VulnType.XSS)
    assert isinstance(verifier, RescanVerifier)
    assert not isinstance(verifier, DiffSemanticVerifier)


def test_factory_ssrf_still_returns_rescan_verifier() -> None:
    """OOB path (SSRF) is unaffected by diff dispatch."""
    from secopent.domain.verification.models import VulnType
    from secopent.infrastructure.oracle.diff_semantic_verifier import (
        DiffSemanticVerifier,
    )
    from secopent.infrastructure.oracle.rescan_verifier import RescanVerifier

    factory = RescanVerifierFactory(
        _FakeRunner(),
        None,
        _FakeCanary(),
        method_registry=_managed_registry(),
        diff_runner_factory=lambda: _FakeDiffRunner(),
    )
    finding = SimpleNamespace(asset="http://t:3000/ssrf?url=x", vuln_type=VulnType.SSRF)
    verifier = factory.for_finding(finding, vuln_type=VulnType.SSRF)
    assert isinstance(verifier, RescanVerifier)
    assert not isinstance(verifier, DiffSemanticVerifier)
