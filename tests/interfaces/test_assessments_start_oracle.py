"""start_assessment threads oracle + confirmed repo into execute_assessment (W3-A T7)."""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from secopent.interfaces.api.main import create_app


@pytest.fixture
def client(tmp_path) -> Iterator[TestClient]:  # type: ignore[no-untyped-def]
    from secopent.infrastructure.db.sqlite import create_sqlite_engine
    engine = create_sqlite_engine(tmp_path / "t7.db")
    app = create_app(engine=engine)
    with TestClient(app) as test_client:
        yield test_client


def _approved_assessment(client: TestClient) -> str:
    """Bootstrap project -> scope -> assessment -> plan -> approval (APPROVED)."""
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


def test_start_threads_oracle_and_confirmed_repo(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST /start passes app.state.oracle + a session-bound confirmed repo."""
    aid = _approved_assessment(client)

    captured: dict[str, object] = {}

    def _fake_execute(**kwargs: object) -> None:
        captured.update(kwargs)
        return None

    import secopent.interfaces.api.routers.assessments as assessments_mod

    monkeypatch.setattr(assessments_mod, "execute_assessment", _fake_execute)

    # Run the background target inline so the captured kwargs are visible
    # before the test exits.
    class _InlineThread:
        def __init__(self, target: object, **_kw: object) -> None:
            self._target = target

        def start(self) -> None:
            # type: ignore[operator]
            self._target()  # type: ignore[operator]

        def join(self, *_a: object, **_k: object) -> None:
            return None

    monkeypatch.setattr(assessments_mod.threading, "Thread", _InlineThread)

    resp = client.post(f"/assessments/{aid}/start", json={"actor_role": "human"})
    assert resp.status_code == 200

    oracle = client.app.state.oracle
    assert captured.get("oracle") is oracle
    assert captured.get("confirmed_finding_repo") is not None


def test_start_without_oracle_in_state_passes_none(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If app.state has no oracle (older app), execute_assessment gets None."""
    aid = _approved_assessment(client)
    # Remove the oracle from state to simulate a non-W3-A app.
    monkeypatch.delattr(client.app.state, "oracle", raising=False)

    captured: dict[str, object] = {}

    def _fake_execute(**kwargs: object) -> None:
        captured.update(kwargs)
        return None

    import secopent.interfaces.api.routers.assessments as assessments_mod

    monkeypatch.setattr(assessments_mod, "execute_assessment", _fake_execute)

    class _InlineThread:
        def __init__(self, target: object, **_kw: object) -> None:
            self._target = target

        def start(self) -> None:
            self._target()  # type: ignore[operator]

        def join(self, *_a: object, **_k: object) -> None:
            return None

    monkeypatch.setattr(assessments_mod.threading, "Thread", _InlineThread)

    resp = client.post(f"/assessments/{aid}/start", json={"actor_role": "human"})
    assert resp.status_code == 200
    assert captured.get("oracle") is None
