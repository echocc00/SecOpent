"""SqlAlchemySignedAuditEventStore.append accepts external session (T3.1).

When ``session`` is provided, the store uses it and does NOT commit (the
caller owns the transaction - v4 same-tx refactor). When omitted, the legacy
path opens a short-lived session and commits immediately.
"""
from __future__ import annotations

import inspect

from sqlalchemy import func, select

from secopent.application.audit_chain import AuditChain, SignedAuditEvent
from secopent.domain.audit.models import AuditEvent
from secopent.infrastructure.audit.key_manager import AuditKeyManager
from secopent.infrastructure.db.session import Database
from secopent.infrastructure.db.signed_audit_models import CoreSignedAuditEvent
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_audit_chain import (
    SqlAlchemySignedAuditEventStore,
)


def _count(session, model) -> int:  # type: ignore[no-untyped-def]
    return int(session.scalar(select(func.count()).select_from(model)))


def _db(tmp_path):  # type: ignore[no-untyped-def]
    return Database(create_sqlite_engine(tmp_path / "t.db"))


def _signed_event(event_id: str = "evt-1") -> SignedAuditEvent:
    ev = AuditEvent.create(
        event_id=event_id,
        actor="t",
        action="t",
        resource_type="t",
        resource_id="t",
        payload={},
        previous_hash="sha256:" + "0" * 64,
    )
    return SignedAuditEvent(event=ev, signature="sig")


def test_append_accepts_optional_keyword_only_session() -> None:
    sig = inspect.signature(SqlAlchemySignedAuditEventStore.append)
    assert "session" in sig.parameters
    assert sig.parameters["session"].default is None
    assert sig.parameters["session"].kind == inspect.Parameter.KEYWORD_ONLY


def test_append_with_session_does_not_commit(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """When session is provided, the store adds to it but does NOT commit."""
    db = _db(tmp_path)
    store = SqlAlchemySignedAuditEventStore(db)
    with db.open_session() as session:
        commits: list[object] = []
        orig_commit = session.commit
        session.commit = lambda: commits.append(1) or orig_commit()  # type: ignore[method-assign]
        store.append(_signed_event(), session=session)
        assert commits == [], "store must NOT commit when session provided"
        # Restore real commit + commit manually to persist.
        session.commit = orig_commit  # type: ignore[method-assign]
        session.commit()
    with db.open_session() as verify:
        assert _count(verify, CoreSignedAuditEvent) == 1


def test_append_without_session_commits_immediately(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Legacy path: no session -> store opens its own + commits."""
    db = _db(tmp_path)
    store = SqlAlchemySignedAuditEventStore(db)
    store.append(_signed_event())
    # Visible from a fresh session (committed).
    with db.open_session() as verify:
        assert _count(verify, CoreSignedAuditEvent) == 1


def test_chain_record_with_session_persists_via_provided_session(
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    """End-to-end: AuditChain.record(session=...) writes via that session."""
    db = _db(tmp_path)
    store = SqlAlchemySignedAuditEventStore(db)
    chain = AuditChain(AuditKeyManager(), store=store)
    with db.open_session() as session:
        chain.record(
            actor="t",
            action="t",
            resource_type="t",
            resource_id="t",
            payload={},
            session=session,
        )
        session.commit()
    with db.open_session() as verify:
        assert _count(verify, CoreSignedAuditEvent) == 1
