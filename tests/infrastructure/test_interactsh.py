"""TDD tests for the Interactsh OOB client (M2 Task 4, ADR H4 self-hosted).

The real interactsh-server runs in Docker (M5); here the client is tested with a
fake transport. The client embeds the canary token as the callback label and
collects only the interactions matching that canary.
"""
from __future__ import annotations

from typing import Any

from secopent.infrastructure.oracle.interactsh import (
    InteractshClient,
    InteractshTransport,
    OobInteraction,
)


class FakeTransport:
    def __init__(self, domain: str, records: list[dict[str, Any]]) -> None:
        self._domain = domain
        self._records = records
        self.polled: list[str] = []

    def register(self) -> str:
        return self._domain

    def poll(self, correlation_domain: str) -> list[dict[str, Any]]:
        self.polled.append(correlation_domain)
        return list(self._records)


def test_allocate_embeds_canary_as_label() -> None:
    client = InteractshClient(FakeTransport("oast.example.com", []))
    assert client.allocate("tok123") == "tok123.oast.example.com"


def test_allocate_correlated_returns_subdomain_and_correlation() -> None:
    """W3-E T1: allocate_correlated returns both the embeddable subdomain and
    the bare correlation domain needed by has_callback."""
    client = InteractshClient(FakeTransport("oast.example.com", []))
    subdomain, correlation = client.allocate_correlated("tok123")
    assert subdomain == "tok123.oast.example.com"
    assert correlation == "oast.example.com"
    # The returned correlation works with has_callback.
    records = [{"unique_id": "tok123", "protocol": "dns", "raw": "x"}]
    client2 = InteractshClient(FakeTransport("oast.example.com", records))
    _, corr = client2.allocate_correlated("tok123")
    assert client2.has_callback("tok123", corr) is True


def test_collect_returns_matching_canary() -> None:
    records = [
        {"unique_id": "tok123", "protocol": "dns", "raw": "query tok123.oast"},
    ]
    client = InteractshClient(FakeTransport("oast.example.com", records))
    interactions = client.collect("tok123", "oast.example.com")
    assert len(interactions) == 1
    assert interactions[0].protocol == "dns"
    assert isinstance(interactions[0], OobInteraction)


def test_collect_filters_other_canaries() -> None:
    records = [
        {"unique_id": "tok123", "protocol": "http", "raw": "a"},
        {"unique_id": "other999", "protocol": "http", "raw": "b"},
    ]
    client = InteractshClient(FakeTransport("oast.example.com", records))
    interactions = client.collect("tok123", "oast.example.com")
    assert [i.unique_id for i in interactions] == ["tok123"]


def test_has_callback_true_when_present() -> None:
    records = [{"unique_id": "tok123", "protocol": "dns", "raw": "x"}]
    client = InteractshClient(FakeTransport("d", records))
    assert client.has_callback("tok123", "d") is True


def test_has_callback_false_when_absent() -> None:
    client = InteractshClient(FakeTransport("d", []))
    assert client.has_callback("tok123", "d") is False


def test_client_accepts_transport_protocol() -> None:
    assert isinstance(FakeTransport("d", []), InteractshTransport)
