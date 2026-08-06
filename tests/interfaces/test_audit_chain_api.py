"""Audit chain lifecycle API: rotate + GDPR redact (v0.5.0 Phase 3, 3.6)."""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.interfaces.api.main import create_app


@pytest.fixture()
def client(tmp_path) -> Iterator[TestClient]:  # type: ignore[no-untyped-def]
    app = create_app(engine=create_sqlite_engine(tmp_path / "audit_api.db"))
    with TestClient(app) as c:
        yield c


def _seed_event(client: TestClient) -> str:
    """Record one event directly on the shared chain; return its id."""
    chain = client.app.state.audit_chain
    signed = chain.record(
        actor="scanner", action="scan.completed", resource_type="assessment",
        resource_id="a1", payload={"note": "ok", "email": "u@x.test"},
    )
    return signed.event.id


def test_rotate_rejects_agent(client: TestClient) -> None:
    resp = client.post("/audit/rotate", json={"actor": "bot", "actor_role": "agent"})
    assert resp.status_code == 403


def test_redact_rejects_agent(client: TestClient) -> None:
    event_id = _seed_event(client)
    resp = client.post("/audit/redact", json={
        "event_id": event_id, "keys": ["email"], "actor": "bot",
        "actor_role": "agent",
    })
    assert resp.status_code == 403


def test_rotate_human_appends_rotation_event(client: TestClient) -> None:
    resp = client.post("/audit/rotate", json={"actor": "ops-alice"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["action"] == "audit.rotated"
    assert body["event_id"]
    assert body["signature"]
    # Rotation never breaks chain verification.
    assert client.app.state.audit_chain.verify() is True


def test_rotate_persists_via_request_transaction(client: TestClient) -> None:
    """The rotation event lands in core_signed_audit_events (request commit)."""
    from sqlalchemy import func, select

    from secopent.infrastructure.db.signed_audit_models import CoreSignedAuditEvent

    client.post("/audit/rotate", json={"actor": "ops-alice"})
    db = client.app.state.db
    with db.unit_of_work() as uow:
        count = uow.session.scalar(
            select(func.count()).select_from(CoreSignedAuditEvent)
        )
    assert count >= 1


def test_redact_masks_pii_in_redacted_export(client: TestClient) -> None:
    event_id = _seed_event(client)
    resp = client.post("/audit/redact", json={
        "event_id": event_id, "keys": ["email"], "actor": "dpo-bob",
    })
    assert resp.status_code == 201, resp.text
    assert resp.json()["action"] == "gdpr.redacted"

    plain = client.get("/audit/chain")
    assert plain.status_code == 200
    original = next(e for e in plain.json() if e["id"] == event_id)
    assert original["payload"]["email"] == "u@x.test"

    redacted = client.get("/audit/chain", params={"redacted": "true"})
    assert redacted.status_code == 200
    masked = next(e for e in redacted.json() if e["id"] == event_id)
    assert masked["payload"]["email"] == "[REDACTED:gdpr]"
    assert masked["payload"]["note"] == "ok"
    # The hash commitment is preserved by redaction.
    assert masked["event_hash"] == original["event_hash"]


def test_redact_unknown_event_404(client: TestClient) -> None:
    resp = client.post("/audit/redact", json={
        "event_id": "evt-nope", "keys": ["email"], "actor": "dpo",
    })
    assert resp.status_code == 404


def test_redact_empty_keys_422(client: TestClient) -> None:
    event_id = _seed_event(client)
    resp = client.post("/audit/redact", json={
        "event_id": event_id, "keys": [], "actor": "dpo",
    })
    assert resp.status_code == 422
