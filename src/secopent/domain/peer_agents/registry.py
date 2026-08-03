# src/secopent/domain/peer_agents/registry.py
"""Deterministic registry of allowed peer agents (curated, no LLM).

Mirrors the VerificationMethodRegistry curation pattern: the registry is
empty by default; entries are added explicitly at the composition root
(P2 registers Strix there). Duplicate name registration is a configuration
error, never a silent override.
"""
from __future__ import annotations

from ..common.errors import DomainError
from .models import PeerAgentDescriptor


class PeerAgentAlreadyRegistered(DomainError):
    """A peer agent with this name is already registered."""


class PeerAgentRegistry:
    """In-memory registry of allowed peer agent descriptors."""

    def __init__(self) -> None:
        self._agents: dict[str, PeerAgentDescriptor] = {}

    def register(self, descriptor: PeerAgentDescriptor) -> None:
        if descriptor.name in self._agents:
            raise PeerAgentAlreadyRegistered(
                f"peer agent already registered: {descriptor.name}"
            )
        self._agents[descriptor.name] = descriptor

    def get(self, name: str) -> PeerAgentDescriptor | None:
        return self._agents.get(name)

    def all(self) -> tuple[PeerAgentDescriptor, ...]:
        return tuple(self._agents.values())


def default_registry() -> PeerAgentRegistry:
    """Empty registry; the composition root registers adopted agents."""
    return PeerAgentRegistry()
