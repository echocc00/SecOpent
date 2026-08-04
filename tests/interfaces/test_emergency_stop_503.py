"""EmergencyStop route 503 when not configured (W4-E T1).

The composition root (W2-A) always wires ``app.state.emergency_stop``. The old
per-call fallback using ``NullPermitRevoker`` was unreachable and misleading
(it silently revoked 0 permits). Now an unconfigured app returns 503 instead.
"""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.interfaces.api.main import create_app


@pytest.fixture
def client(tmp_path) -> Iterator[TestClient]:  # type: ignore[no-untyped-def]
    app = create_app(engine=create_sqlite_engine(tmp_path / "w4e1.db"))
    with TestClient(app) as c:
        yield c


def _assessment(client: TestClient) -> str:
    project = client.post("/projects", json={"name": "Acme"}).json()
    scope = client.post(
        "/scopes/draft",
        json={"project_id": project["id"], "include": ["https://acme.test"]},
    ).json()
    return client.post(
        "/assessments",
        json={"project_id": project["id"], "scope_snapshot_id": scope["id"]},
    ).json()["id"]


def test_emergency_stop_503_when_unconfigured(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    aid = _assessment(client)
    monkeypatch.delattr(client.app.state, "emergency_stop", raising=False)
    resp = client.post(
        f"/assessments/{aid}/stop",
        json={"actor": "analyst", "reason": "test"},
    )
    assert resp.status_code == 503
