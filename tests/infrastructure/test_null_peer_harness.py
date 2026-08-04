"""NullPeerAgentHarness graceful degradation (W4-A T1)."""
from __future__ import annotations

from secopent.application.peer_agents import PeerAgentHarness
from secopent.domain.peer_agents.models import (
    PeerAgentBudget,
    PeerAgentDescriptor,
    PeerAgentRun,
    PeerAgentTrustLevel,
)
from secopent.infrastructure.peer_agents.null_harness import NullPeerAgentHarness


def _run() -> PeerAgentRun:
    return PeerAgentRun(
        id="run-1",
        agent_name="strix",
        agent_version="1.4.1",
        assessment_id="asm-1",
        targets=("10.0.0.1",),
        budget=PeerAgentBudget(max_wall_seconds=60, max_cost_units=1.0),
        permit_id="permit-1",
    )


def _descriptor() -> PeerAgentDescriptor:
    return PeerAgentDescriptor(
        name="strix",
        version="1.4.1",
        license="mit",
        trust_level=PeerAgentTrustLevel.ADOPTED_EXTERNAL,
        capabilities=("web",),
        cost_class="llm",
        default_budget=PeerAgentBudget(max_wall_seconds=60, max_cost_units=1.0),
    )


def test_execute_returns_empty_report() -> None:
    harness = NullPeerAgentHarness()
    report = harness.execute(_run(), _descriptor())
    assert report.run_id == "run-1"
    assert report.findings == ()
    assert report.wall_seconds == 0.0
    assert report.cost_units == 0.0
    assert report.exit_code == 0


def test_terminate_returns_false_no_containers() -> None:
    harness = NullPeerAgentHarness()
    assert harness.terminate("run-1") is False


def test_satisfies_peer_agent_harness_protocol() -> None:
    assert isinstance(NullPeerAgentHarness(), PeerAgentHarness)
