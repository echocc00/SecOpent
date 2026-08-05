"""UnitOfWork: explicit commit/rollback boundary (v0.3.0 T3)."""
from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import select

from secopent.domain.common.canonical import utc_now
from secopent.infrastructure.db.core_models import CoreProject
from secopent.infrastructure.db.session import Database
from secopent.infrastructure.db.sqlite import create_sqlite_engine


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    return Database(create_sqlite_engine(tmp_path / "uow.db"))


def _project(pid: str) -> CoreProject:
    return CoreProject(id=pid, name=pid, status="active", created_at=utc_now())


def _get(db: Database, pid: str) -> CoreProject | None:
    with db.unit_of_work() as uow:
        return uow.session.scalar(select(CoreProject).where(CoreProject.id == pid))


def test_commits_on_clean_exit(db: Database) -> None:
    with db.unit_of_work() as uow:
        uow.session.add(_project("p1"))
    assert _get(db, "p1") is not None


def test_rolls_back_on_exception(db: Database) -> None:
    with pytest.raises(RuntimeError, match="boom"), db.unit_of_work() as uow:
        uow.session.add(_project("p2"))
        raise RuntimeError("boom")
    assert _get(db, "p2") is None


def test_session_unreachable_after_exit(db: Database) -> None:
    with db.unit_of_work() as uow:
        assert uow.session is not None
    with pytest.raises(RuntimeError, match="outside its context block"):
        _ = uow.session


def test_explicit_phase_commit_visible_to_other_connections(db: Database) -> None:
    """commit() ends the current tx mid-block; other connections see it even
    before the UoW exits (this is what releases the WAL write lock)."""
    with db.unit_of_work() as uow:
        uow.session.add(_project("p3"))
        uow.commit()
        assert _get(db, "p3") is not None  # nested UoW = fresh connection
        uow.session.add(_project("p4"))
    assert _get(db, "p4") is not None  # final commit on exit still happens


def test_consecutive_uows_work(db: Database) -> None:
    with db.unit_of_work() as uow:
        uow.session.add(_project("p5"))
    with db.unit_of_work() as uow:
        uow.session.add(_project("p6"))
    assert _get(db, "p5") is not None
    assert _get(db, "p6") is not None
