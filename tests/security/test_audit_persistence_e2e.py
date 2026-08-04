"""Signed audit chain persistence E2E (W3-C T5).

Exercises the full persistence path (SqlAlchemy store + persisted audit key)
across a simulated restart: GDPR redaction state is re-derived from persisted
events, so export stays masked after a fresh process.
"""
from __future__ import annotations

import pytest

from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.interfaces.api.main import create_app


def test_gdpr_redaction_survives_restart(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "redact.db"
    key_path = tmp_path / "audit.key"
    monkeypatch.setenv("SECOPTENT_AUDIT_KEY_PATH", str(key_path))

    engine1 = create_sqlite_engine(db_path)
    app1 = create_app(engine=engine1)
    signed = app1.state.audit_chain.record(
        actor="a", action="scan", resource_type="r", resource_id="1",
        payload={"email": "user@example.com", "note": "ok"},
    )
    app1.state.audit_chain.redact_pii(signed.event.id, keys=frozenset({"email"}))

    # Restart: fresh process, same DB + key.
    engine2 = create_sqlite_engine(db_path)
    app2 = create_app(engine=engine2)
    chain2 = app2.state.audit_chain

    # The redaction event survived + the redaction state was re-derived.
    exported = chain2.export(redacted=True)
    assert exported[0].payload["email"] == "[REDACTED:gdpr]"
    assert exported[0].payload["note"] == "ok"
    # The chain still verifies (key persisted).
    assert chain2.verify() is True
    # The gdpr.redacted event itself is in the persisted chain.
    assert any(e.action == "gdpr.redacted" for e in chain2.events())
