"""Peer-agent launch wiring E2E (W4-A T6).

Contract-level: with the feature flag on, ``GET /peer-agents`` lists strix and
``POST /assessments/{id}/peer-runs`` against an approved assessment's scope
returns an empty ``PeerRunOutcome`` (NullPeerAgentHarness). No real Docker or
peer images required - the point is to prove the composition root -> router ->
service -> harness path is wired through ``create_app``.
"""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from secopent.interfaces.api.main import create_app


@pytest.fixture
def client(tmp_path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("SECOPTENT_PEER_AGENTS_ENABLED", "1")
    # No LLM_API_KEY -> composition root falls back to NullPeerAgentHarness
    # (with a warning), keeping this a pure wiring test: no real Docker or
    # peer images are invoked. Set LLM_API_KEY in a real deployment to switch
    # to ContainerPeerAgentHarness.
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    from secopent.infrastructure.db.sqlite import create_sqlite_engine

    engine = create_sqlite_engine(tmp_path / "w4a6.db")
    app = create_app(engine=engine)
    with TestClient(app) as test_client:
        yield test_client


def _assessment_with_scope(client: TestClient) -> str:
    """Bootstrap project -> scope -> assessment (enough for the launch route)."""
    project = client.post("/projects", json={"name": "Acme"}).json()
    scope = client.post(
        "/scopes/draft",
        json={"project_id": project["id"], "include": ["https://acme.test"]},
    ).json()
    assessment = client.post(
        "/assessments",
        json={"project_id": project["id"], "scope_snapshot_id": scope["id"]},
    ).json()
    return assessment["id"]


def test_get_agents_lists_strix(client: TestClient) -> None:
    resp = client.get("/peer-agents")
    assert resp.status_code == 200
    names = [a["name"] for a in resp.json()]
    assert "strix" in names


def test_launch_returns_empty_outcome_with_null_harness(
    client: TestClient,
) -> None:
    aid = _assessment_with_scope(client)
    resp = client.post(
        f"/assessments/{aid}/peer-runs",
        json={
            "agent_name": "strix",
            "targets": ["https://acme.test"],
            "asset_type": "web_app",
            "actor": "analyst",
            "permit_id": "permit-1",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["run"]["assessment_id"] == aid
    assert body["run"]["agent_name"] == "strix"
    assert body["run"]["status"] == "completed"
    assert body["observations"] == []
    assert body["rejected"] == []


def test_launch_404_when_assessment_missing(client: TestClient) -> None:
    resp = client.post(
        "/assessments/nope/peer-runs",
        json={
            "agent_name": "strix",
            "targets": ["https://acme.test"],
            "asset_type": "web_app",
            "actor": "analyst",
            "permit_id": "permit-1",
        },
    )
    assert resp.status_code == 404
