"""v3 regression: the background executor must see QUEUED, not stale APPROVED.

The race: ``service.start()`` writes APPROVED->QUEUED in the request session
but does not commit; the daemon opens its own connection and reads stale
APPROVED. SQLite WAL hides uncommitted writes from new connections, so the
daemon's ``mark_running`` raises ``"cannot run from approved"``.

Fix history: v0.2.0.1 added an explicit ``session.commit()`` before spawning
the thread; v0.3.0 T5 replaced the raw thread with FastAPI BackgroundTasks
(which run after the response) - the explicit commit is KEPT because FastAPI
0.115 runs yield-dependency teardown (the DbSession commit) AFTER background
tasks, so without it the daemon's UnitOfWork session would still read stale
APPROVED.
"""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.interfaces.api.main import create_app


@pytest.fixture
def client(tmp_path) -> Iterator[TestClient]:  # type: ignore[no-untyped-def]
    """Real file DB (not in-memory) so the daemon's UnitOfWork session is a
    separate connection - the precondition for the v3 race under SQLite WAL."""
    engine = create_sqlite_engine(tmp_path / "v3.db")
    app = create_app(engine=engine)
    with TestClient(app) as c:
        yield c


def _approved_assessment(client: TestClient) -> str:
    project = client.post("/projects", json={"name": "Acme"}).json()
    scope = client.post(
        "/scopes/draft",
        json={"project_id": project["id"], "include": ["https://acme.test"]},
    ).json()
    assessment = client.post(
        "/assessments",
        json={"project_id": project["id"], "scope_snapshot_id": scope["id"]},
    ).json()
    client.post(
        "/plans",
        json={
            "assessment_id": assessment["id"],
            "steps": [{"key": "recon", "runner": "nuclei", "risk": "low"}],
        },
    )
    client.post(
        "/approvals",
        json={
            "assessment_id": assessment["id"],
            "approved_by": "human",
            "approved_risks": ["low"],
            "approved_capabilities": ["network.scan"],
        },
    )
    return assessment["id"]


def test_daemon_sees_queued_not_stale_approved(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The daemon's session must read QUEUED. Without ``session.commit()``
    before the background task runs, SQLite WAL hides the uncommitted QUEUED
    write from the daemon's new connection -> daemon sees stale APPROVED.
    TestClient executes background tasks synchronously before returning the
    response, so no thread patching is needed."""
    aid = _approved_assessment(client)
    seen: list[str] = []

    import secopent.interfaces.api.routers.assessments as assessments_mod

    def _capture(**kwargs: object) -> None:
        repo = kwargs.get("assessment_repo")
        if repo is not None:
            asm = repo.get(kwargs.get("assessment_id"))
            if asm is not None:
                seen.append(asm.status.value)

    monkeypatch.setattr(assessments_mod, "execute_assessment", _capture)

    resp = client.post(f"/assessments/{aid}/start", json={"actor_role": "human"})
    assert resp.status_code == 200, resp.text
    assert seen == ["queued"], (
        f"v3 race: daemon saw stale status {seen} (expected ['queued']); "
        "session.commit() missing before the background task runs"
    )
