"""Composition root: signed audit chain persists across restart (W3-C T4)."""
from __future__ import annotations

import pytest

from secopent.application.audit_chain import AuditChain
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_audit_chain import (
    SqlAlchemySignedAuditEventStore,
)
from secopent.interfaces.api.main import create_app


def test_audit_chain_has_persistent_store(tmp_path) -> None:  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "t.db")
    app = create_app(engine=engine)
    assert isinstance(app.state.audit_chain, AuditChain)
    # The store is wired (events persist to the DB).
    app.state.audit_chain.record(
        actor="a", action="x", resource_type="r", resource_id="1", payload={}
    )
    assert app.state.audit_chain.verify() is True


def test_signed_chain_survives_restart_with_persisted_key(
    tmp_path, monkeypatch: pytest.MonkeyPatch  # type: ignore[no-untyped-def]
) -> None:
    """With SECOPTENT_AUDIT_KEY_PATH set, events + key survive a fresh create_app."""
    db_path = tmp_path / "restart.db"
    key_path = tmp_path / "audit.key"
    monkeypatch.setenv("SECOPTENT_AUDIT_KEY_PATH", str(key_path))

    engine1 = create_sqlite_engine(db_path)
    app1 = create_app(engine=engine1)
    app1.state.audit_chain.record(
        actor="a", action="boot", resource_type="r", resource_id="1", payload={}
    )
    app1.state.audit_chain.record_permit_nonce(
        actor="w", job_id="j", permit_nonce="nonce-restart"
    )
    assert key_path.exists()  # key material persisted

    # Simulate a restart: fresh engine over the same DB file + same key path.
    engine2 = create_sqlite_engine(db_path)
    app2 = create_app(engine=engine2)
    chain2 = app2.state.audit_chain

    # Events survived.
    assert len(chain2.events()) == 2
    # Signatures still verify (key was persisted + reloaded).
    assert chain2.verify() is True
    # Permit nonces survived.
    assert "nonce-restart" in chain2.permit_nonces()


def test_audit_store_is_sqlalchemy_backed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "t.db")
    app = create_app(engine=engine)
    # The store attached to the chain is the SqlAlchemy implementation.
    assert isinstance(app.state.audit_chain._store, SqlAlchemySignedAuditEventStore)
