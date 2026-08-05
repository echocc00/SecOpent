"""DatabaseAuditRecorder accepts external session (T4, W4-A v4-class fix)."""
from __future__ import annotations

import inspect

from sqlalchemy import func, select

from secopent.infrastructure.audit.database_recorder import DatabaseAuditRecorder
from secopent.infrastructure.db.core_models import CoreAuditEvent
from secopent.infrastructure.db.session import Database
from secopent.infrastructure.db.sqlite import create_sqlite_engine


def _db(tmp_path):  # type: ignore[no-untyped-def]
    return Database(create_sqlite_engine(tmp_path / "t.db"))


def _count(session, model) -> int:  # type: ignore[no-untyped-def]
    return int(session.scalar(select(func.count()).select_from(model)))


def test_record_accepts_optional_keyword_only_session() -> None:
    sig = inspect.signature(DatabaseAuditRecorder.record)
    assert "session" in sig.parameters
    assert sig.parameters["session"].default is None
    assert sig.parameters["session"].kind == inspect.Parameter.KEYWORD_ONLY


def test_record_with_session_does_not_commit(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """When session is provided, the recorder uses it but does NOT commit."""
    db = _db(tmp_path)
    recorder = DatabaseAuditRecorder(db)
    with db.open_session() as session:
        commits: list[object] = []
        orig_commit = session.commit
        session.commit = lambda: commits.append(1) or orig_commit()  # type: ignore[method-assign]
        recorder.record(
            actor="t", action="t", resource_type="t",
            resource_id="t", payload={}, session=session,
        )
        assert commits == [], "recorder must NOT commit when session provided"
        session.commit = orig_commit  # type: ignore[method-assign]
        session.commit()
    with db.open_session() as verify:
        assert _count(verify, CoreAuditEvent) == 1


def test_record_without_session_commits_immediately(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Legacy path: no session -> recorder opens its own + commits."""
    db = _db(tmp_path)
    recorder = DatabaseAuditRecorder(db)
    recorder.record(
        actor="t", action="t", resource_type="t",
        resource_id="t", payload={},
    )
    with db.open_session() as verify:
        assert _count(verify, CoreAuditEvent) == 1
