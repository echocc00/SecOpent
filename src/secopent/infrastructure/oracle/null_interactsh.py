# src/secopent/infrastructure/oracle/null_interactsh.py
"""NullInteractshTransport: no-op OOB transport (W3-E T4).

Used when no self-hosted interactsh-server is configured (pre-M5). ``register``
returns a placeholder correlation domain; ``poll`` never returns any interaction,
so OOB verification is wired but always reports FAILURE (no callback). Swap for
the real HTTP transport once the interactsh-server is deployed (M5, gated by
``SECOPTENT_INTERACTSH_SERVER_URL``).
"""
from __future__ import annotations

from typing import Any


class NullInteractshTransport:
    """No-op InteractshTransport: allocates domains, never observes callbacks."""

    def register(self) -> str:
        return "oast.null"

    def poll(self, correlation_domain: str) -> list[dict[str, Any]]:
        return []
