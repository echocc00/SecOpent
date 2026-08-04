"""HttpInteractshTransport (W4-C T1)."""
from __future__ import annotations

import httpx
import pytest

from secopent.infrastructure.oracle.http_interactsh import HttpInteractshTransport
from secopent.infrastructure.oracle.interactsh import InteractshTransport


def _transport(handler) -> HttpInteractshTransport:  # type: ignore[no-untyped-def]
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return HttpInteractshTransport("http://oast.test", client=client)


def test_register_returns_correlation_domain() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.method == "POST"
        assert req.url.path == "/register"
        return httpx.Response(200, json={"correlation_domain": "abc123.oast.test"})

    assert _transport(handler).register() == "abc123.oast.test"


def test_register_composes_from_correlation_id_and_domain() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"correlation_id": "cid1", "domain": "oast.test"})

    assert _transport(handler).register() == "cid1.oast.test"


def test_register_raises_on_missing_domain() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"message": "ok"})

    with pytest.raises(ValueError):
        _transport(handler).register()


def test_register_raises_on_http_error() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    with pytest.raises(httpx.HTTPStatusError):
        _transport(handler).register()


def test_poll_returns_normalized_records() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.method == "GET"
        assert req.url.path == "/poll"
        assert req.url.params["id"] == "abc123.oast.test"
        return httpx.Response(
            200,
            json=[
                {
                    "unique-id": "canary1",
                    "protocol": "dns",
                    "raw-request": "Q canary1.abc123.oast.test",
                }
            ],
        )

    records = _transport(handler).poll("abc123.oast.test")
    assert len(records) == 1
    assert records[0]["unique_id"] == "canary1"
    assert records[0]["protocol"] == "dns"
    assert "canary1.abc123.oast.test" in records[0]["raw"]


def test_poll_returns_empty_when_no_interactions() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    assert _transport(handler).poll("abc123.oast.test") == []


def test_satisfies_interactsh_transport_protocol() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    assert isinstance(_transport(handler), InteractshTransport)
