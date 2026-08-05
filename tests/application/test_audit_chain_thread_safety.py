"""AuditChain thread-safety (v0.3.0 T2).

Recorders are concurrent by design: the daemon thread, request threads
(emergency stop triggers ``record`` via the shared chain), and - from v0.3.0 -
the outbox worker. Before T2, ``_counter += 1`` and the store append were
unguarded, so concurrent recorders could mint duplicate event ids or persist
rows out of chain order (breaking ``_load_from_store`` reconstruction).
"""
from __future__ import annotations

import threading

from secopent.application.audit_chain import AuditChain, SignedAuditEvent
from secopent.infrastructure.audit.key_manager import AuditKeyManager


class _FakeStore:
    def __init__(self) -> None:
        self.rows: list[SignedAuditEvent] = []
        self._lock = threading.Lock()

    def append(self, signed: SignedAuditEvent, *, session: object = None) -> None:
        with self._lock:
            self.rows.append(signed)

    def load_all(self) -> tuple[SignedAuditEvent, ...]:
        with self._lock:
            return tuple(self.rows)


def test_concurrent_records_keep_chain_consistent() -> None:
    store = _FakeStore()
    chain = AuditChain(AuditKeyManager(), store=store)
    n_threads, n_records = 4, 50

    def worker(thread_id: int) -> None:
        for i in range(n_records):
            chain.record(
                actor=f"t{thread_id}", action="x", resource_type="r",
                resource_id=f"{thread_id}-{i}", payload={},
            )

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total = n_threads * n_records
    events = chain.events()
    assert len(events) == total
    ids = [e.id for e in events]
    assert len(set(ids)) == total, "event ids must be unique under concurrency"
    assert set(ids) == {f"evt-{i}" for i in range(1, total + 1)}, "contiguous ids"
    assert chain.verify() is True
    # Persisted order must match chain order (restart rebuild depends on it).
    assert [row.event.id for row in store.rows] == ids


def test_concurrent_readers_do_not_raise() -> None:
    """Readers snapshot under the lock - no torn reads while a writer runs."""
    chain = AuditChain(AuditKeyManager())
    stop = threading.Event()
    errors: list[Exception] = []

    def writer() -> None:
        for i in range(200):
            chain.record(
                actor="w", action="x", resource_type="r",
                resource_id=str(i), payload={},
            )
        stop.set()

    def reader() -> None:
        try:
            while not stop.is_set():
                chain.verify()
                chain.events()
                chain.export(redacted=True)
                chain.permit_nonces()
        except Exception as exc:  # noqa: BLE001 - record any reader failure
            errors.append(exc)

    readers = [threading.Thread(target=reader) for _ in range(3)]
    writer_thread = threading.Thread(target=writer)
    for t in readers:
        t.start()
    writer_thread.start()
    writer_thread.join()
    for t in readers:
        t.join()
    assert not errors, f"readers raised during concurrent writes: {errors[:3]}"


def test_concurrent_permit_nonce_records_no_lost_updates() -> None:
    chain = AuditChain(AuditKeyManager())
    n_threads, n_records = 4, 25

    def worker(thread_id: int) -> None:
        for i in range(n_records):
            chain.record_permit_nonce(
                actor="system", job_id=f"job-{thread_id}-{i}",
                permit_nonce=f"nonce-{thread_id}-{i}",
            )

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(chain.permit_nonces()) == n_threads * n_records
    assert chain.verify() is True
