# tests/scripts/test_migrate_db.py
"""Tests for the SQLite -> DB data migration (T15 / cross-cutting §④).

Uses two SQLite stores (source with data, destination schema-only) to verify the
table copy + row-count verification logic. The PostgreSQL path uses the same
``migrate_tables``/``verify_counts`` functions via a ``postgresql://`` dest URL
(exercised by the CI dual-DB matrix).
"""
from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from secopent.application.audit_chain import AuditChain
from secopent.infrastructure.db.session import init_db
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAuditRepository,
)
from secopent.scripts.migrate_db import (
    count_rows,
    migrate_tables,
    shared_tables,
    verify_counts,
)


class _NullSigner:
    def sign(self, message: bytes) -> str:
        return "sig"

    def verify(self, message: bytes, signature: str) -> bool:
        return True


def _seed_source(db_path: Path, n_events: int = 5):  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(db_path)
    init_db(engine)
    session = Session(engine)
    chain = AuditChain(_NullSigner())
    repo = SqlAlchemyAuditRepository(session)
    for i in range(n_events):
        signed = chain.record(
            actor="a", action="x", resource_type="t", resource_id=f"r{i}", payload={"i": i}
        )
        repo.add(signed.event)
    session.commit()
    session.close()
    return engine


def test_migration_copies_all_rows_and_verifies(tmp_path: Path) -> None:
    source = _seed_source(tmp_path / "src.db", n_events=5)
    dest = create_sqlite_engine(tmp_path / "dst.db")
    init_db(dest)  # schema only, no data

    tables = shared_tables(source, dest)
    assert "core_audit_events" in tables
    assert "alembic_version" not in tables  # bookkeeping excluded

    counts = migrate_tables(source, dest, tables)
    assert counts["core_audit_events"] == 5
    assert verify_counts(source, dest, tables) == []  # no mismatches
    assert count_rows(dest, "core_audit_events") == 5

    source.dispose()
    dest.dispose()


def test_verify_counts_detects_a_mismatch(tmp_path: Path) -> None:
    source = _seed_source(tmp_path / "src.db", n_events=3)
    dest = create_sqlite_engine(tmp_path / "dst.db")
    init_db(dest)  # empty -> counts differ

    mismatches = verify_counts(source, dest, ["core_audit_events"])
    assert mismatches == ["core_audit_events: source=3 dest=0"]

    source.dispose()
    dest.dispose()
