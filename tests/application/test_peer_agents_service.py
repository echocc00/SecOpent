# tests/application/test_peer_agents_service.py
"""Application tests for PeerAgentService (integration spec §5 P0)."""
from __future__ import annotations


class TestInMemoryPeerRunRepository:
    def test_add_get_save_roundtrip(self) -> None:
        from secopent.application.ports.peer_runs import InMemoryPeerRunRepository
        from secopent.domain.peer_agents.models import (
            PeerAgentBudget,
            PeerAgentRun,
            PeerRunStatus,
        )

        repo = InMemoryPeerRunRepository()
        run = PeerAgentRun(
            id="run-1",
            agent_name="strix",
            agent_version="1.4.1",
            assessment_id="asmt-1",
            targets=("http://t",),
            budget=PeerAgentBudget(max_wall_seconds=60, max_cost_units=1.0),
            permit_id="p-1",
        )
        repo.add(run)
        assert repo.get("run-1") == run
        updated = PeerAgentRun(
            id=run.id,
            agent_name=run.agent_name,
            agent_version=run.agent_version,
            assessment_id=run.assessment_id,
            targets=run.targets,
            budget=run.budget,
            permit_id=run.permit_id,
            status=PeerRunStatus.COMPLETED,
        )
        repo.save(updated)
        assert repo.get("run-1").status is PeerRunStatus.COMPLETED
