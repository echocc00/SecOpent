"""peer_agents router registration on root + /api (W4-A T4)."""
from __future__ import annotations

from fastapi.testclient import TestClient

from secopent.interfaces.api.main import create_app


def test_peer_agents_route_registered_on_root() -> None:
    client = TestClient(create_app())
    # Registered -> 503 (service disabled by default until W4-A T5 wires it),
    # NOT 404 (which would mean the router was never included).
    assert client.get("/peer-agents").status_code == 503


def test_peer_agents_route_registered_on_api_subapp() -> None:
    client = TestClient(create_app())
    assert client.get("/api/peer-agents").status_code == 503
