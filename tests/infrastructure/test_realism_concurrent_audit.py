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


def _make_signed(event_id: str):  # type: ignore[no-untyped-def]
    from secopent.application.audit_chain import SignedAuditEvent
    from secopent.domain.audit.models import AuditEvent

    ev = AuditEvent.create(
        event_id=event_id,
        actor="t", action="t", resource_type="t", resource_id="t",
        payload={}, previous_hash="sha256:" + "0" * 64,
    )
    return SignedAuditEvent(event=ev, signature="sig")
