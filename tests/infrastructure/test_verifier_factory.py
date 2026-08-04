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
