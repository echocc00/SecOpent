"""peer_agents router (W4-A T3).

Tests the service-only routes (list agents, list/get/stop runs) + the 503
degradation path. The launch route (DB-backed: fetches scope + catalog) is
covered by the W4-A T6 wiring E2E.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from secopent.application.audit import AuditService
from secopent.application.peer_agents import PeerAgentService
from secopent.domain.peer_agents.models import (
    PeerAgentBudget,
    PeerAgentDescriptor,
    PeerAgentRun,
    PeerAgentTrustLevel,
    PeerRunStatus,
)
from secopent.domain.peer_agents.registry import PeerAgentRegistry
from secopent.infrastructure.peer_agents.in_memory_peer_runs import (
    InMemoryPeerRunRepository,
)
from secopent.infrastructure.peer_agents.null_harness import NullPeerAgentHarness
from secopent.interfaces.api.routers.peer_agents import router as peer_agents_router


def _descriptor() -> PeerAgentDescriptor:
    return PeerAgentDescriptor(
        name="strix",
        version="1.4.1",
        license="Apache-2.0",
        trust_level=PeerAgentTrustLevel.ADOPTED_EXTERNAL,
        capabilities=("web", "api"),
        cost_class="llm_tokens",
        default_budget=PeerAgentBudget(max_wall_seconds=1800, max_cost_units=100.0),
    )


def _audit_service() -> AuditService:
    from secopent.domain.audit.models import GENESIS_HASH, AuditEvent

    class _MemoryAuditRepo:
        def __init__(self) -> None:
            self.events: list[AuditEvent] = []

        def add(self, e: AuditEvent) -> None:
            self.events.append(e)

        def list_events(self) -> list[AuditEvent]:
            return list(self.events)

        def last_hash(self) -> str:
            return (
                self.events[-1].event_hash.removeprefix("sha256:")
                if self.events
                else GENESIS_HASH
            )

    return AuditService(repo=_MemoryAuditRepo())


def _run(run_id: str = "r1", assessment_id: str = "a1") -> PeerAgentRun:
    return PeerAgentRun(
        id=run_id,
        agent_name="strix",
        agent_version="1.4.1",
        assessment_id=assessment_id,
        targets=("http://t",),
        budget=PeerAgentBudget(max_wall_seconds=60, max_cost_units=1.0),
        permit_id="p1",
        status=PeerRunStatus.RUNNING,
    )


def _app_with_service(service: PeerAgentService | None) -> FastAPI:
    app = FastAPI()
    app.include_router(peer_agents_router)
    app.state.peer_agent_service = service
    return app


def _seeded_service() -> PeerAgentService:
    registry = PeerAgentRegistry()
    registry.register(_descriptor())
    runs = InMemoryPeerRunRepository()
    runs.add(_run())
    return PeerAgentService(
        registry=registry,
        harness=NullPeerAgentHarness(),
        audit=_audit_service(),
        runs=runs,
    )


def test_list_agents_returns_registered_descriptors() -> None:
    client = TestClient(_app_with_service(_seeded_service()))
    resp = client.get("/peer-agents")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["name"] == "strix"
    assert body[0]["trust_level"] == "adopted_external_agent"


def test_list_runs_returns_runs_for_assessment() -> None:
    client = TestClient(_app_with_service(_seeded_service()))
    resp = client.get("/assessments/a1/peer-runs")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["id"] == "r1"


def test_get_run_returns_run() -> None:
    client = TestClient(_app_with_service(_seeded_service()))
    resp = client.get("/peer-runs/r1")
    assert resp.status_code == 200
    assert resp.json()["id"] == "r1"


def test_get_run_404_when_missing() -> None:
    client = TestClient(_app_with_service(_seeded_service()))
    resp = client.get("/peer-runs/nope")
    assert resp.status_code == 404


def test_stop_run_returns_terminated_flag() -> None:
    client = TestClient(_app_with_service(_seeded_service()))
    resp = client.post(
        "/peer-runs/r1/stop",
        json={"actor": "analyst", "reason": "done"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["run_id"] == "r1"
    # NullPeerAgentHarness.terminate returns False (nothing to kill).
    assert body["terminated"] is False


def test_stop_run_404_when_missing() -> None:
    client = TestClient(_app_with_service(_seeded_service()))
    resp = client.post(
        "/peer-runs/nope/stop",
        json={"actor": "analyst", "reason": "done"},
    )
    assert resp.status_code == 404


def test_all_routes_503_when_service_disabled() -> None:
    client = TestClient(_app_with_service(None))
    assert client.get("/peer-agents").status_code == 503
    assert client.get("/assessments/a1/peer-runs").status_code == 503
    assert client.get("/peer-runs/r1").status_code == 503
    assert (
        client.post(
            "/peer-runs/r1/stop", json={"actor": "a", "reason": "r"}
        ).status_code
        == 503
    )
