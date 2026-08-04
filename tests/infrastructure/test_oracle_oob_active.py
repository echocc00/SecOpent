"""OOB canary branch fires end-to-end via HttpInteractshTransport (W4-C T4).

Wires the real production components together - RescanVerifierFactory (which
embeds the OOB placeholder, W4-C T2) + HttpInteractshTransport against a stub
HTTP server (W4-C T1) + RescanVerifier's OOB branch (W3-E) - and proves a
finding with ``oob_window_seconds > 0`` verifies SUCCESS when the stub server
returns a callback matching the canary token.
"""
from __future__ import annotations

from types import SimpleNamespace

import httpx

from secopent.domain.verification.models import (
    CandidateFinding,
    ReproductionStatus,
    VerificationMethod,
    VulnType,
)
from secopent.infrastructure.oracle.http_interactsh import HttpInteractshTransport
from secopent.infrastructure.oracle.interactsh import InteractshClient
from secopent.infrastructure.oracle.verifier_factory import RescanVerifierFactory


class _FakeRunner:
    def scan(self, **_kwargs: object) -> object:  # noqa: ARG002
        class _R:
            observations = ()
            stdout = ""

        return _R()


def _stub_transport(canary_token: str) -> HttpInteractshTransport:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/register":
            return httpx.Response(200, json={"correlation_domain": "abc.oast.test"})
        if req.url.path == "/poll":
            return httpx.Response(
                200,
                json=[
                    {
                        "unique_id": canary_token,
                        "protocol": "dns",
                        "raw": "Q " + canary_token + ".abc.oast.test",
                    }
                ],
            )
        return httpx.Response(404)

    return HttpInteractshTransport(
        "http://oast.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_oob_branch_fires_success_when_callback_present() -> None:
    canary_token = "tok-xyz"
    interactsh = InteractshClient(_stub_transport(canary_token))
    factory = RescanVerifierFactory(
        _FakeRunner(),  # type: ignore[arg-type]
        None,
        canary=None,
        interactsh=interactsh,
    )
    verifier = factory.for_finding(SimpleNamespace(asset=_candidate().target))
    verifier._oob_sleep = lambda _s: None  # skip the OOB wait (default is bound at import)
    method = VerificationMethod(
        vuln_type=VulnType.SSRF, default_n=1, oob_window_seconds=5
    )
    status = verifier.reproduce(
        _candidate(), method, canary_token=canary_token
    )
    assert status is ReproductionStatus.SUCCESS


def test_oob_branch_fires_failure_when_no_callback() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/register":
            return httpx.Response(200, json={"correlation_domain": "abc.oast.test"})
        return httpx.Response(200, json=[])  # no interactions

    transport = HttpInteractshTransport(
        "http://oast.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    interactsh = InteractshClient(transport)
    factory = RescanVerifierFactory(
        _FakeRunner(),  # type: ignore[arg-type]
        None,
        canary=None,
        interactsh=interactsh,
    )
    verifier = factory.for_finding(SimpleNamespace(asset=_candidate().target))
    verifier._oob_sleep = lambda _s: None
    method = VerificationMethod(
        vuln_type=VulnType.SSRF, default_n=1, oob_window_seconds=5
    )
    status = verifier.reproduce(_candidate(), method, canary_token="tok-none")
    assert status is ReproductionStatus.FAILURE


def _candidate() -> CandidateFinding:
    return CandidateFinding(
        id="c-1",
        observation_id="o-1",
        vuln_type=VulnType.SSRF,
        target="http://t:3000/path",
    )
