# src/secopent/infrastructure/peer_agents/in_memory_peer_runs.py
"""In-memory PeerRunRepository (W3-B, moved out of application/ports/).

Dict-backed reference implementation of the PeerRunRepository Protocol; serves
Lite mode and all tests. Moved out of ports/ so application/ports/ holds only
Protocols/DTOs - concrete implementations live in infrastructure (same pattern
as InMemoryPermitRevoker in infrastructure/safety/).
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

    def list_for_assessment(
        self, assessment_id: str
    ) -> tuple[PeerAgentRun, ...]:
        return tuple(
            run for run in self._runs.values() if run.assessment_id == assessment_id
        )
