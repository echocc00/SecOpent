# tests/interfaces/test_api_start.py
"""P0 /assessments/{id}/start API boundary tests (v0.1.2).

These verify the LLM boundary (agent -> 403) and state guard (non-APPROVED ->
422) on the new start endpoint. Both fail before the background executor is
spawned, so no Docker is needed. The happy-path execution + finding correlation
is covered by tests/application/test_execution.py (with a fake step runner).
"""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from secopent.interfaces.api.main import create_app


@pytest.fixture
def client(tmp_path) -> Iterator[TestClient]:  # type: ignore[no-untyped-def]
    from secopent.infrastructure.db.sqlite import create_sqlite_engine
    engine = create_sqlite_engine(tmp_path / "start.db")
    app = create_app(engine=engine)
    with TestClient(app) as test_client:
        yield test_client


def _make_assessment(client: TestClient) -> str:
    """Create a project + scope + assessment (DRAFT, no plan/approval)."""
    p = client.post("/projects", json={"name": "t"}).json()
    sc = client.post("/scopes/draft", json={
        "project_id": p["id"], "include": ["http://localhost:3000"], "ports": [3000],
        "limits": {"rps": 10, "concurrency": 2, "max_requests": 100},
    }).json()
    a = client.post("/assessments", json={
        "project_id": p["id"], "scope_snapshot_id": sc["id"],
        "mode": "approval", "approved_by": "analyst",
    }).json()
    return a["id"]


def test_start_rejects_agent(client: TestClient) -> None:
    """agent actor_role -> 403 (LLM boundary; triggers real scans)."""
    aid = _make_assessment(client)
    resp = client.post(f"/assessments/{aid}/start", json={"actor_role": "agent"})
    assert resp.status_code == 403


def test_start_rejects_non_approved(client: TestClient) -> None:
    """DRAFT assessment (no plan/approval) -> 422 (state guard)."""
    aid = _make_assessment(client)
    resp = client.post(f"/assessments/{aid}/start", json={"actor_role": "human"})
    assert resp.status_code == 422


def test_start_unknown_assessment_404(client: TestClient) -> None:
    resp = client.post("/assessments/asm-nope/start", json={"actor_role": "human"})
    assert resp.status_code == 404
