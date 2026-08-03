# src/secopent/application/ports/peer_runs.py
"""In-memory PeerRunRepository implementation (P0).

The SQLite-backed implementation lands with P2 wiring (see plan #4); the
in-memory repo serves Lite mode and all tests. Kept in application/ports
alongside the Protocol usage, mirroring how other Lite-mode in-memory
repositories are provided.
"""
from __future__ import annotations

from ...domain.peer_agents.models import PeerAgentRun


class InMemoryPeerRunRepository:
    """Dict-backed PeerRunRepository (satisfies the Protocol structurally)."""

    def __init__(self) -> None:
        self._runs: dict[str, PeerAgentRun] = {}

    def add(self, run: PeerAgentRun) -> None:
        self._runs[run.id] = run

    def save(self, run: PeerAgentRun) -> None:
        self._runs[run.id] = run

    def get(self, run_id: str) -> PeerAgentRun | None:
        return self._runs.get(run_id)
