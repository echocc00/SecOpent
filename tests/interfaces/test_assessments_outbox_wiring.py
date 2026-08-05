"""start_assessment wires the lifespan-activated outbox into the executor (T4).

The outbox recorder becomes visible to routers only once the lifespan runs
(startup drain done + worker thread up). Apps served via a lifespan context
get it; bare apps keep the legacy direct-audit path.
"""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from secopent.interfaces.api.main import create_app
from secopent.interfaces.api.routers import assessments as assessments_mod


@pytest.fixture()
def client(tmp_path) -> Iterator[TestClient]:  # type: ignore[no-untyped-def]
    from secopent.infrastructure.db.sqlite import create_sqlite_engine

    engine = create_sqlite_engine(tmp_path / "outbox_wiring.db")
    app = create_app(engine=engine)
    with TestClient(app) as test_client:  # lifespan activates the outbox
        yield test_client


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
            "approved_by": "human-reviewer",
            "approved_risks": ["low"],
            "approved_capabilities": ["network.scan"],
        },
    )
    return assessment["id"]


def test_start_passes_activated_outbox_to_executor(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def _fake_execute(**kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(assessments_mod, "execute_assessment", _fake_execute)

    aid = _approved_assessment(client)
    resp = client.post(f"/assessments/{aid}/start", json={"actor_role": "human"})
    assert resp.status_code == 200
    assert captured.get("audit_outbox") is not None


def test_outbox_stays_inactive_without_lifespan(
    tmp_path, monkeypatch: pytest.MonkeyPatch  # type: ignore[no-untyped-def]
) -> None:
    """No lifespan -> no activation -> executor gets None (legacy path)."""
    from secopent.infrastructure.db.sqlite import create_sqlite_engine

    engine = create_sqlite_engine(tmp_path / "no_lifespan.db")
    bare_client = TestClient(create_app(engine=engine))  # no context manager
    captured: dict[str, object] = {}

    def _fake_execute(**kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(assessments_mod, "execute_assessment", _fake_execute)

    aid = _approved_assessment(bare_client)
    resp = bare_client.post(
        f"/assessments/{aid}/start", json={"actor_role": "human"}
    )
    assert resp.status_code == 200
    assert captured.get("audit_outbox") is None
