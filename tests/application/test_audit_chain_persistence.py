"""AuditChain persistence: load/append via a store port (W3-C T1)."""
from __future__ import annotations

from secopent.application.audit_chain import AuditChain, SignedAuditEvent
from secopent.application.ports.audit_chain import SignedAuditEventStore
from secopent.infrastructure.audit.key_manager import AuditKeyManager


class _FakeStore:
    def __init__(self) -> None:
        self.rows: list[SignedAuditEvent] = []

    def append(self, signed: SignedAuditEvent, *, session: object = None) -> None:
        self.rows.append(signed)

    def load_all(self) -> tuple[SignedAuditEvent, ...]:
        return tuple(self.rows)


def test_init_loads_existing_events_from_store() -> None:
    store = _FakeStore()
    keys = AuditKeyManager()  # shared key (key persistence is T4's concern)
    chain1 = AuditChain(keys, store=store)
    chain1.record(actor="a", action="x", resource_type="r", resource_id="1", payload={})
    chain1.record(actor="a", action="y", resource_type="r", resource_id="2", payload={})
    assert len(store.rows) == 2

    chain2 = AuditChain(keys, store=store)
    assert len(chain2.events()) == 2
    assert chain2.verify() is True
    assert {e.action for e in chain2.events()} == {"x", "y"}


def test_record_appends_to_store() -> None:
    store = _FakeStore()
    chain = AuditChain(AuditKeyManager(), store=store)
    chain.record(actor="a", action="x", resource_type="r", resource_id="1", payload={})
    assert len(store.rows) == 1
    assert store.rows[0].event.action == "x"
    assert store.rows[0].signature  # non-empty


def test_counter_continues_after_load() -> None:
    store = _FakeStore()
    keys = AuditKeyManager()
    chain1 = AuditChain(keys, store=store)
    chain1.record(actor="a", action="x", resource_type="r", resource_id="1", payload={})
    chain2 = AuditChain(keys, store=store)
    signed = chain2.record(actor="a", action="y", resource_type="r", resource_id="2", payload={})
    assert signed.event.id == "evt-2"  # counter continues from loaded length
    assert chain2.verify() is True


def test_permit_nonces_survive_reload() -> None:
    store = _FakeStore()
    keys = AuditKeyManager()
    chain1 = AuditChain(keys, store=store)
    chain1.record_permit_nonce(actor="w", job_id="j-1", permit_nonce="nonce-xyz")
    chain2 = AuditChain(keys, store=store)
    assert "nonce-xyz" in chain2.permit_nonces()


def test_redactions_rederived_on_load() -> None:
    store = _FakeStore()
    keys = AuditKeyManager()
    chain1 = AuditChain(keys, store=store)
    signed = chain1.record(
        actor="a", action="scan", resource_type="r", resource_id="1",
        payload={"email": "u@x", "note": "ok"},
    )
    chain1.redact_pii(signed.event.id, keys=frozenset({"email"}))

    chain2 = AuditChain(keys, store=store)
    exported = chain2.export(redacted=True)
    assert exported[0].payload["email"] == "[REDACTED:gdpr]"
    assert exported[0].payload["note"] == "ok"


def test_store_is_optional_backward_compat() -> None:
    """No store -> pure in-memory (pre-W3-C behavior)."""
    chain = AuditChain(AuditKeyManager())
    chain.record(actor="a", action="x", resource_type="r", resource_id="1", payload={})
    assert chain.verify() is True
    assert isinstance(_FakeStore(), SignedAuditEventStore)  # Protocol satisfied


class _SessionCapturingStore:
    """Records the ``session`` kwarg each append receives (3.6, v0.5.0)."""

    def __init__(self) -> None:
        self.rows: list[SignedAuditEvent] = []
        self.sessions: list[object] = []

    def append(self, signed: SignedAuditEvent, *, session: object = None) -> None:
        self.sessions.append(session)
        self.rows.append(signed)

    def load_all(self) -> tuple[SignedAuditEvent, ...]:
        return tuple(self.rows)


def test_rotate_threads_session_to_store() -> None:
    """rotate(session=...) joins the caller's transaction (3.6)."""
    store = _SessionCapturingStore()
    chain = AuditChain(AuditKeyManager(), store=store)
    chain.record(actor="a", action="x", resource_type="r", resource_id="1", payload={})
    signed = chain.rotate(session="caller-session")
    assert signed.event.action == "audit.rotated"
    assert store.sessions[-1] == "caller-session"
    assert chain.verify() is True


def test_rotate_default_session_none_backward_compat() -> None:
    store = _SessionCapturingStore()
    chain = AuditChain(AuditKeyManager(), store=store)
    chain.record(actor="a", action="x", resource_type="r", resource_id="1", payload={})
    chain.rotate()
    assert store.sessions[-1] is None  # store manages its own transaction


def test_redact_pii_threads_session_to_store() -> None:
    store = _SessionCapturingStore()
    chain = AuditChain(AuditKeyManager(), store=store)
    signed = chain.record(
        actor="a", action="scan", resource_type="r", resource_id="1",
        payload={"email": "u@x"},
    )
    chain.redact_pii(signed.event.id, keys=frozenset({"email"}), session="caller-session")
    assert store.sessions[-1] == "caller-session"
    assert chain.export(redacted=True)[0].payload["email"] == "[REDACTED:gdpr]"


def test_rotate_records_actor() -> None:
    """The API passes the human actor; default stays audit_chain."""
    chain = AuditChain(AuditKeyManager())
    assert chain.rotate(actor="ops-alice").event.actor == "ops-alice"
    assert chain.rotate().event.actor == "audit_chain"
