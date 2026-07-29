# tests/interfaces/test_updates_publish.py
"""Integration tests for the updates router (P3 §3.4-3/-4).

Exercises the REAL signed-bundle path end-to-end: ``POST /updates/publish``
signs an intel bundle with the server's §3.8 Ed25519 key, verifies it, and
activates it so ``GET /updates/active`` returns a real bundle. ``/updates/health``
is asserted on its deterministic detectors; OSV reachability is patched so the
test makes no real network call.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import secopent.interfaces.api.routers.updates as updates_router
from secopent.interfaces.api.main import create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


class _Reachable:
    """Stand-in for OsvReachabilityChecker: always reachable, no network."""

    def is_reachable(self, source: str) -> bool:
        return True


@pytest.fixture(autouse=True)
def _no_network_probe(monkeypatch):
    monkeypatch.setattr(updates_router, "OsvReachabilityChecker", _Reachable)


def test_publish_then_active_returns_real_bundle(client: TestClient) -> None:
    published = client.post("/updates/publish", json={"actor_role": "human"})
    assert published.status_code == 201, published.text
    body = published.json()
    assert body["bundle_id"].startswith("intel-")
    assert body["digest"].startswith("sha256:")
    assert body["staged_at"] is not None

    active = client.get("/updates/active").json()
    assert active["active_bundle_id"] == body["bundle_id"]
    assert active["bundle"] is not None
    assert active["bundle"]["digest"] == body["digest"]


def test_publish_actor_defaults_to_human(client: TestClient) -> None:
    assert client.post("/updates/publish", json={}).status_code == 201


def test_publish_agent_is_forbidden(client: TestClient) -> None:
    assert (
        client.post("/updates/publish", json={"actor_role": "agent"}).status_code == 403
    )


def test_health_reports_real_stale_detector(client: TestClient) -> None:
    response = client.get("/updates/health")
    assert response.status_code == 200
    kinds = {a["kind"] for a in response.json()["alerts"]}
    # No local nuclei-templates clone configured -> git freshness reports stale.
    assert "source_stale" in kinds
    # Reachability is patched reachable -> no unreachable alert.
    assert "source_unreachable" not in kinds


def test_health_signature_valid_after_publish(client: TestClient) -> None:
    client.post("/updates/publish", json={"actor_role": "human"})
    kinds = {a["kind"] for a in client.get("/updates/health").json()["alerts"]}
    # A successful publish records a valid verification -> no signature alert.
    assert "signature_invalid" not in kinds
