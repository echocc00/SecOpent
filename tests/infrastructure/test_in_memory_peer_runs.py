"""InMemoryPeerRunRepository.list_for_assessment (W4-A T2)."""
from __future__ import annotations

from secopent.domain.peer_agents.models import (
    PeerAgentBudget,
    PeerAgentRun,
)
from secopent.infrastructure.peer_agents.in_memory_peer_runs import (
    InMemoryPeerRunRepository,
)


def _run(run_id: str, assessment_id: str) -> PeerAgentRun:
    return PeerAgentRun(
        id=run_id,
        agent_name="strix",
        agent_version="1.4.1",
        assessment_id=assessment_id,
        targets=("10.0.0.1",),
        budget=PeerAgentBudget(max_wall_seconds=60, max_cost_units=1.0),
        permit_id="permit-1",
    )


def test_list_for_assessment_returns_only_that_assessments_runs() -> None:
    repo = InMemoryPeerRunRepository()
    repo.add(_run("r1", "a1"))
    repo.add(_run("r2", "a1"))
    repo.add(_run("r3", "a2"))

    listed = repo.list_for_assessment("a1")
    assert {r.id for r in listed} == {"r1", "r2"}


def test_list_for_assessment_empty_when_no_match() -> None:
    repo = InMemoryPeerRunRepository()
    repo.add(_run("r1", "a1"))
    assert repo.list_for_assessment("other") == ()


def test_list_for_assessment_empty_repo_returns_empty() -> None:
    repo = InMemoryPeerRunRepository()
    assert repo.list_for_assessment("a1") == ()
