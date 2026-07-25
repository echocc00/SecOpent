# src/secopent/infrastructure/oracle/interactsh.py
"""Self-hosted Interactsh out-of-band client (ADR H4, §9 OOB verification).

Out-of-band verification (SSRF / blind SQLi / blind XSS / RCE / deserialization)
needs a callback channel. Public OOB services are unreliable from domestic
networks, so Interactsh is self-hosted. The real server runs in Docker (M5 E2E);
here the client is built against an injected ``InteractshTransport`` so it is
testable without a server.

A canary token is embedded as the left-most label of the callback domain
(``<canary>.<correlation-domain>``). ``collect`` polls the transport and returns
only the interactions whose label matches the canary, so one correlation domain
can serve many concurrent verifications.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class OobInteraction:
    """A single out-of-band callback correlated to a canary token."""

    protocol: str  # "dns" / "http" / "smtp"
    unique_id: str  # the full callback label that fired
    raw: str


@runtime_checkable
class InteractshTransport(Protocol):
    """The server-facing surface (real: HTTP to interactsh-server; tests: fake)."""

    def register(self) -> str:
        """Allocate a correlation domain (e.g. ``abcd1234.oast.example.com``)."""
        ...

    def poll(self, correlation_domain: str) -> list[dict[str, Any]]:
        """Return raw interaction records for a correlation domain."""
        ...


class InteractshClient:
    """Allocate OOB callback domains and collect canary-correlated callbacks."""

    def __init__(self, transport: InteractshTransport, *, server_url: str = "") -> None:
        self._transport = transport
        self._server_url = server_url

    def allocate(self, canary_token: str) -> str:
        """Return the callback domain for a canary: ``<canary>.<correlation-domain>``."""
        domain = self._transport.register()
        return f"{canary_token}.{domain}"

    def collect(self, canary_token: str, correlation_domain: str) -> tuple[OobInteraction, ...]:
        """Return the interactions whose label is exactly this canary token."""
        records = self._transport.poll(correlation_domain)
        interactions: list[OobInteraction] = []
        for record in records:
            label = str(record.get("unique_id", ""))
            if label != canary_token:
                continue
            interactions.append(
                OobInteraction(
                    protocol=str(record.get("protocol", "")),
                    unique_id=label,
                    raw=str(record.get("raw", "")),
                )
            )
        return tuple(interactions)

    def has_callback(
        self, canary_token: str, correlation_domain: str
    ) -> bool:
        """Whether at least one callback fired for this canary token."""
        return len(self.collect(canary_token, correlation_domain)) > 0
