"""Daemon netns degradation (v0.5.1 F2): a netns failure must not kill the
assessment - it audits the degradation and falls back to the default-netns
enforcer (the NAS incident's fix: hardening never blocks the core scan)."""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from secopent.infrastructure.db.core_models import CoreAuditEvent
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.egress.netns_isolator import NetnsHandle, NetnsIsolator
from secopent.interfaces.api.main import create_app
from secopent.interfaces.api.routers import assessments as assessments_mod


@pytest.fixture()
def client(tmp_path) -> Iterator[TestClient]:  # type: ignore[no-untyped-def]
    app = create_app(engine=create_sqlite_engine(tmp_path / "degrade.db"))
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


def test_netns_failure_degrades_and_records_audit(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def _fake_execute(**kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(assessments_mod, "execute_assessment", _fake_execute)
    monkeypatch.setattr(NetnsIsolator, "is_supported", lambda self: True)
    monkeypatch.setattr(
        NetnsIsolator, "create",
        lambda self, assessment_id: (_ for _ in ()).throw(RuntimeError("no netns")),
    )

    aid = _approved_assessment(client)
    resp = client.post(f"/assessments/{aid}/start", json={"actor_role": "human"})
    assert resp.status_code == 200, resp.text

    # The executor still ran, with the default-netns enforcer (degraded).
    assert captured.get("nft_scope_enforcer") is not None
    # The degradation was audited into the queryable log (request transaction).
    db = client.app.state.db
    with db.unit_of_work() as uow:
        actions = [
            r.action for r in uow.session.scalars(select(CoreAuditEvent)).all()
        ]
    assert "netns.unavailable.degraded" in actions


def test_netns_success_path_does_not_audit_degradation(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: when the netns path succeeds, no degradation event is written."""
    captured: dict[str, object] = {}

    def _fake_execute(**kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(assessments_mod, "execute_assessment", _fake_execute)
    monkeypatch.setattr(NetnsIsolator, "is_supported", lambda self: True)
    monkeypatch.setattr(
        NetnsIsolator, "create",
        lambda self, assessment_id: NetnsHandle(name=f"secopent-{assessment_id}"),
    )
    monkeypatch.setattr(NetnsIsolator, "destroy", lambda self, handle: None)

    # Keep the real make_nft_enforcer so the netns path is exercised for real.
    aid = _approved_assessment(client)
    resp = client.post(f"/assessments/{aid}/start", json={"actor_role": "human"})
    assert resp.status_code == 200, resp.text

    db = client.app.state.db
    with db.unit_of_work() as uow:
        actions = [
            r.action for r in uow.session.scalars(select(CoreAuditEvent)).all()
        ]
    assert "netns.unavailable.degraded" not in actions