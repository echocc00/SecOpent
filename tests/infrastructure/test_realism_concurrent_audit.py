"""Production-realism regression: merged-transaction audit path (T5, v4).

Exercises the v4 root-cause fix: ``_audit_record`` writes both
``core_audit_events`` + ``core_signed_audit_events`` in the SAME session /
SAME transaction. Uses a real file DB (not in-memory) + the default file-based
pool so the test environment matches production (the gap that masked v4 in the
original 1190 unit tests using ``StaticPool``).

Asserts: N audit events -> N rows in BOTH tables, no ``OperationalError``,
committed atomically in one transaction.
"""
from __future__ import annotations

import pytest
from sqlalchemy import func, select

from secopent.application.audit import AuditService
from secopent.application.audit_chain import AuditChain
from secopent.infrastructure.audit.key_manager import AuditKeyManager
from secopent.infrastructure.db.core_models import CoreAuditEvent
from secopent.infrastructure.db.session import Database
from secopent.infrastructure.db.signed_audit_models import CoreSignedAuditEvent
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_audit_chain import (
    SqlAlchemySignedAuditEventStore,
)
from secopent.infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAuditRepository,
)


def _count(session, model) -> int:  # type: ignore[no-untyped-def]
    return int(session.scalar(select(func.count()).select_from(model)))


@pytest.mark.realism
def test_merged_audit_transaction_no_lock_contention(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """N audit events via _audit_record pattern: both tables populated, no
    OperationalError. This is the v4 regression for the merged-transaction
    path (T3 full refactor)."""
    db = Database(create_sqlite_engine(tmp_path / "realism.db"))
    store = SqlAlchemySignedAuditEventStore(db)
    chain = AuditChain(AuditKeyManager(), store=store)

    # Simulate the daemon's _audit_record pattern: one session, N events,
    # one commit at the end. Both tables written via the same session.
    n = 50
    with db.open_session() as session:
        repo = SqlAlchemyAuditRepository(session)
        for i in range(n):
            # Queryable log (core_audit_events) via the repo's session.
            AuditService(repo).record(
                actor="system", action=f"test.event.{i}",
                resource_type="test", resource_id=f"r{i}", payload={"i": i},
            )
            # Signed chain (core_signed_audit_events) via the SAME session.
            chain.record(
                actor="system", action=f"test.event.{i}",
                resource_type="test", resource_id=f"r{i}",
                payload={"i": i}, session=session,
            )
        session.commit()

    # Both tables have exactly N rows (atomic, one transaction).
    with db.open_session() as verify:
        assert _count(verify, CoreAuditEvent) == n
        assert _count(verify, CoreSignedAuditEvent) == n


@pytest.mark.realism
def test_concurrent_store_appends_no_operational_error(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Store-level concurrency: multiple threads each open their own session
    and append. With busy_timeout=60s (T2) + WAL, none should fail with
    ``database is locked``. This tests the SQL layer's ability to handle
    concurrent writers (the v4 symptom) independent of the chain's single-
    thread design."""
    import threading

    db = Database(create_sqlite_engine(tmp_path / "storm.db"))
    store = SqlAlchemySignedAuditEventStore(db)
    errors: list[Exception] = []

    def worker(thread_id: int, count: int) -> None:
        try:
            for i in range(count):
                store.append(  # type: ignore[arg-type]
                    _make_signed(f"t{thread_id}-{i}"),
                )
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(t, 20)) for t in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, f"concurrent store appends failed: {errors[:3]}"
    with db.open_session() as verify:
        assert _count(verify, CoreSignedAuditEvent) == 80


@pytest.mark.realism
def test_concurrent_chain_records_persist_in_order(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Chain-level concurrency (v0.3.0 T2): 4 threads recording through ONE
    AuditChain backed by the real file store -> persisted rows are unique,
    contiguous, and in chain order, and a chain rebuilt from the store
    verifies (signatures + hash chain intact)."""
    import threading

    db = Database(create_sqlite_engine(tmp_path / "chain_race.db"))
    store = SqlAlchemySignedAuditEventStore(db)
    keys = AuditKeyManager()
    chain = AuditChain(keys, store=store)
    n_threads, n_records = 4, 25
    errors: list[Exception] = []

    def worker(thread_id: int) -> None:
        try:
            for i in range(n_records):
                chain.record(
                    actor=f"t{thread_id}", action="concurrent.event",
                    resource_type="test", resource_id=f"{thread_id}-{i}",
                    payload={"i": i},
                )
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, f"concurrent chain.record failed: {errors[:3]}"

    total = n_threads * n_records
    with db.open_session() as verify:
        assert _count(verify, CoreSignedAuditEvent) == total
    # A fresh chain rebuilt from the store verifies (order + signatures).
    rebuilt = AuditChain(keys, store=SqlAlchemySignedAuditEventStore(db))
    assert len(rebuilt.events()) == total
    assert rebuilt.verify() is True


def _make_signed(event_id: str):  # type: ignore[no-untyped-def]
    from secopent.application.audit_chain import SignedAuditEvent
    from secopent.domain.audit.models import AuditEvent

    ev = AuditEvent.create(
        event_id=event_id,
        actor="t", action="t", resource_type="t", resource_id="t",
        payload={}, previous_hash="sha256:" + "0" * 64,
    )
    return SignedAuditEvent(event=ev, signature="sig")
