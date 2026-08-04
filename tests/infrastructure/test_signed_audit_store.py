"""SqlAlchemySignedAuditEventStore round-trip (W3-C T3)."""
from __future__ import annotations

from secopent.application.audit_chain import AuditChain
from secopent.application.ports.audit_chain import SignedAuditEventStore
from secopent.infrastructure.audit.key_manager import AuditKeyManager
from secopent.infrastructure.db.session import Database
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_audit_chain import (
    SqlAlchemySignedAuditEventStore,
)


def _store(tmp_path) -> tuple[SqlAlchemySignedAuditEventStore, Database]:  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "audit.db")
    db = Database(engine)
    return SqlAlchemySignedAuditEventStore(db), db


def test_store_satisfies_protocol(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store, _ = _store(tmp_path)
    assert isinstance(store, SignedAuditEventStore)


def test_append_then_load_all_round_trip(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store, _ = _store(tmp_path)
    keys = AuditKeyManager()
    chain = AuditChain(keys, store=store)
    chain.record(actor="a", action="x", resource_type="r", resource_id="1", payload={"n": 1})
    chain.record(actor="a", action="y", resource_type="r", resource_id="2", payload={"n": 2})

    loaded = store.load_all()
    assert len(loaded) == 2
    # Chain order preserved.
    assert [s.event.action for s in loaded] == ["x", "y"]
    # Signatures carried.
    assert all(s.signature for s in loaded)
    # Event fields round-trip.
    assert loaded[0].event.payload == {"n": 1}


def test_new_chain_loads_persisted_events_and_verifies(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A fresh AuditChain over the same store sees prior events (restart)."""
    store, _ = _store(tmp_path)
    keys = AuditKeyManager()  # shared key (key persistence is T4)
    chain1 = AuditChain(keys, store=store)
    chain1.record(actor="a", action="x", resource_type="r", resource_id="1", payload={})
    chain1.record_permit_nonce(actor="w", job_id="j", permit_nonce="n1")

    chain2 = AuditChain(keys, store=store)
    assert len(chain2.events()) == 2
    assert chain2.verify() is True
    assert "n1" in chain2.permit_nonces()


def test_load_all_empty_store_returns_empty(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store, _ = _store(tmp_path)
    assert store.load_all() == ()
