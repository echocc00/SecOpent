"""Transactional outbox: recorder + worker drain semantics (v0.3.0 T4)."""
from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import func, select

from secopent.application.audit_chain import AuditChain
from secopent.infrastructure.audit.key_manager import AuditKeyManager
from secopent.infrastructure.audit.outbox_recorder import OutboxRecorder
from secopent.infrastructure.audit.outbox_worker import OutboxWorker
from secopent.infrastructure.db.core_models import CoreAuditEvent
from secopent.infrastructure.db.outbox_models import CoreAuditOutbox
from secopent.infrastructure.db.session import Database
from secopent.infrastructure.db.signed_audit_models import CoreSignedAuditEvent
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_audit_chain import (
    SqlAlchemySignedAuditEventStore,
)


def _count(session, model) -> int:  # type: ignore[no-untyped-def]
    return int(session.scalar(select(func.count()).select_from(model)))


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    return Database(create_sqlite_engine(tmp_path / "outbox.db"))


@pytest.fixture()
def chain(db: Database) -> AuditChain:
    return AuditChain(AuditKeyManager(), store=SqlAlchemySignedAuditEventStore(db))


def _record_kwargs(action: str) -> dict[str, object]:
    return {
        "actor": "system", "action": action, "resource_type": "assessment",
        "resource_id": "a1", "payload": {"k": action},
    }


def test_recorder_with_session_joins_caller_transaction(db: Database) -> None:
    recorder = OutboxRecorder(db)
    with db.unit_of_work() as uow:
        recorder.record(session=uow.session, **_record_kwargs("x.y"))  # type: ignore[arg-type]
        with db.unit_of_work() as other:
            assert _count(other.session, CoreAuditOutbox) == 0  # uncommitted
    with db.unit_of_work() as check:
        rows = check.session.scalars(select(CoreAuditOutbox)).all()
    assert len(rows) == 1
    assert rows[0].status == "pending"
    assert rows[0].action == "x.y"


def test_recorder_rollback_drops_the_row(db: Database) -> None:
    recorder = OutboxRecorder(db)
    with pytest.raises(RuntimeError, match="boom"), db.unit_of_work() as uow:
        recorder.record(session=uow.session, **_record_kwargs("x.y"))  # type: ignore[arg-type]
        raise RuntimeError("boom")
    with db.unit_of_work() as check:
        assert _count(check.session, CoreAuditOutbox) == 0


def test_recorder_without_session_commits_own_transaction(db: Database) -> None:
    OutboxRecorder(db).record(**_record_kwargs("own.tx"))
    with db.unit_of_work() as check:
        assert _count(check.session, CoreAuditOutbox) == 1


def test_worker_drains_to_both_audit_tables(db: Database, chain: AuditChain) -> None:
    recorder = OutboxRecorder(db)
    for action in ("a.one", "a.two", "a.three"):
        recorder.record(**_record_kwargs(action))

    drained = OutboxWorker(db, chain, poll_interval=0.01).drain_pending()
    assert drained == 3

    with db.unit_of_work() as check:
        assert _count(check.session, CoreAuditEvent) == 3
        assert _count(check.session, CoreSignedAuditEvent) == 3
        rows = check.session.scalars(
            select(CoreAuditOutbox).order_by(CoreAuditOutbox.id)
        ).all()
    assert [r.status for r in rows] == ["done"] * 3
    assert all(r.processed_at is not None for r in rows)
    # Drain order == insertion order (the chain rebuilds from row order).
    assert [e.action for e in chain.events()] == ["a.one", "a.two", "a.three"]
    assert chain.verify() is True


def test_worker_drain_is_idempotent_when_empty(db: Database, chain: AuditChain) -> None:
    worker = OutboxWorker(db, chain, poll_interval=0.01)
    assert worker.drain_pending() == 0
    assert worker.drain_pending() == 0


def test_poison_row_flagged_and_neighbours_still_drain(
    db: Database, chain: AuditChain
) -> None:
    recorder = OutboxRecorder(db)
    for action in ("ok.before", "poison", "ok.after"):
        recorder.record(**_record_kwargs(action))

    class _PoisonChain:
        """Wraps the real chain but rejects the 'poison' action."""

        def __init__(self, inner: AuditChain) -> None:
            self._inner = inner

        def record(self, **kwargs: object) -> object:
            if kwargs.get("action") == "poison":
                raise RuntimeError("poisoned event")
            return self._inner.record(**kwargs)  # type: ignore[arg-type]

    worker = OutboxWorker(db, _PoisonChain(chain), poll_interval=0.01)  # type: ignore[arg-type]
    assert worker.drain_pending() == 3

    with db.unit_of_work() as check:
        rows = check.session.scalars(
            select(CoreAuditOutbox).order_by(CoreAuditOutbox.id)
        ).all()
    assert [r.status for r in rows] == ["done", "failed", "done"]
    assert rows[1].error is not None and "poisoned" in rows[1].error
    # The failed row is NOT re-drained (no duplicates on later polls).
    assert worker.drain_pending() == 0
    assert [e.action for e in chain.events()] == ["ok.before", "ok.after"]
