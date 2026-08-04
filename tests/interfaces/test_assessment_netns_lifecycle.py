"""Per-assessment netns lifecycle in start_assessment (W4-B T2/T3)."""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.egress.netns_isolator import NetnsHandle, NetnsIsolator
from secopent.interfaces.api.main import create_app


@pytest.fixture
def client(tmp_path) -> Iterator[TestClient]:  # type: ignore[no-untyped-def]
    app = create_app(engine=create_sqlite_engine(tmp_path / "w4b2.db"))
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


def _inline_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    import secopent.interfaces.api.routers.assessments as assessments_mod

    class _InlineThread:
        def __init__(self, target: object, **_kw: object) -> None:
            self._target = target

        def start(self) -> None:
            self._target()  # type: ignore[operator]

        def join(self, *_a: object, **_k: object) -> None:
            return None

    monkeypatch.setattr(assessments_mod.threading, "Thread", _InlineThread)


def _fake_execute_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    import secopent.interfaces.api.routers.assessments as assessments_mod

    monkeypatch.setattr(assessments_mod, "execute_assessment", lambda **_kw: None)


class _RecordingIsolator(NetnsIsolator):
    def __init__(self) -> None:
        super().__init__()
        self.created: list[str] = []
        self.destroyed: list[str] = []

    def create(self, assessment_id: str) -> NetnsHandle:  # type: ignore[override]
        name = self._netns_name(assessment_id)
        self.created.append(name)
        return NetnsHandle(name=name)

    def destroy(self, handle: NetnsHandle) -> None:  # type: ignore[override]
        self.destroyed.append(handle.name)


def test_netns_created_and_destroyed_on_linux(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    aid = _approved_assessment(client)
    monkeypatch.setattr(NetnsIsolator, "is_supported", lambda self: True)
    isolator = _RecordingIsolator()
    client.app.state.netns_isolator = isolator
    enforcer_netns: list[str | None] = []
    real_make = client.app.state.make_nft_enforcer

    def _rec_make(netns: str | None) -> object:
        enforcer_netns.append(netns)
        return real_make(netns)

    client.app.state.make_nft_enforcer = _rec_make
    _fake_execute_noop(monkeypatch)
    _inline_thread(monkeypatch)

    resp = client.post(f"/assessments/{aid}/start", json={"actor_role": "human"})
    assert resp.status_code == 200
    assert len(isolator.created) == 1
    assert isolator.created[0].startswith("secopent-")
    assert enforcer_netns == [isolator.created[0]]
    assert isolator.destroyed == isolator.created


def test_netns_not_created_on_non_linux(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    aid = _approved_assessment(client)
    monkeypatch.setattr(NetnsIsolator, "is_supported", lambda self: False)
    isolator = _RecordingIsolator()
    client.app.state.netns_isolator = isolator
    enforcer_netns: list[str | None] = []
    real_make = client.app.state.make_nft_enforcer

    def _rec_make(netns: str | None) -> object:
        enforcer_netns.append(netns)
        return real_make(netns)

    client.app.state.make_nft_enforcer = _rec_make
    _fake_execute_noop(monkeypatch)
    _inline_thread(monkeypatch)

    resp = client.post(f"/assessments/{aid}/start", json={"actor_role": "human"})
    assert resp.status_code == 200
    assert isolator.created == []
    assert isolator.destroyed == []
    assert enforcer_netns == [None]


def test_netns_destroyed_even_when_execute_raises(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cleanup runs in finally: the netns is destroyed even if execute raises."""
    app = create_app(engine=create_sqlite_engine(tmp_path / "w4b3.db"))
    with TestClient(app, raise_server_exceptions=False) as client:
        aid = _approved_assessment(client)
        monkeypatch.setattr(NetnsIsolator, "is_supported", lambda self: True)
        isolator = _RecordingIsolator()
        client.app.state.netns_isolator = isolator
        _inline_thread(monkeypatch)

        import secopent.interfaces.api.routers.assessments as assessments_mod

        monkeypatch.setattr(
            assessments_mod,
            "execute_assessment",
            lambda **_kw: (_ for _ in ()).throw(RuntimeError("scan failed")),
        )

        resp = client.post(f"/assessments/{aid}/start", json={"actor_role": "human"})
        # The inline thread re-raised into the route -> 500, but the finally
        # destroyed the netns before the exception propagated.
        assert resp.status_code == 500
        assert len(isolator.created) == 1
        assert isolator.destroyed == isolator.created

