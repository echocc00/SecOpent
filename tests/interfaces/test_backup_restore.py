# tests/interfaces/test_backup_restore.py
"""Tests for the backup/restore CLI + audit-chain verification (P3 §3.8 / T8).

Covers the restore safety contract:
- a valid chain verifies; an empty store is trivially valid;
- backup -> restore round-trips and the restored store's audit chain verifies,
  with every event preserved;
- a tampered backup is rejected BEFORE the live store is touched;
- ``--include-secrets`` requires an encrypted-store source (the Fernet master
  key is never written into a backup).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from secopent.application.audit_chain import AuditChain
from secopent.infrastructure.audit.chain_verify import verify_db_audit_chain
from secopent.infrastructure.db.session import init_db
from secopent.infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAuditRepository,
)
from secopent.interfaces.cli.main import _cmd_backup, _cmd_restore


class _NullSigner:
    """Signs nothing meaningful; the DB restore check verifies hashes only."""

    def sign(self, message: bytes) -> str:
        return "sig"

    def verify(self, message: bytes, signature: str) -> bool:
        return True


def _seed_chain_db(db_path: Path, n: int = 3) -> None:
    engine = create_engine(f"sqlite:///{db_path.absolute().as_posix()}")
    init_db(engine)
    session = sessionmaker(bind=engine)()
    chain = AuditChain(_NullSigner())
    repo = SqlAlchemyAuditRepository(session)
    for i in range(n):
        signed = chain.record(
            actor="tester",
            action=f"act.{i}",
            resource_type="test",
            resource_id=f"r{i}",
            payload={"i": i},
        )
        repo.add(signed.event)
    session.commit()
    session.close()
    engine.dispose()


def _count_events(db_path: Path) -> int:
    engine = create_engine(f"sqlite:///{db_path.absolute().as_posix()}")
    session = sessionmaker(bind=engine)()
    try:
        return len(SqlAlchemyAuditRepository(session).list_events())
    finally:
        session.close()
        engine.dispose()


# --- verify_db_audit_chain ---------------------------------------------------


def test_verify_chain_valid(tmp_path: Path) -> None:
    db = tmp_path / "valid.db"
    _seed_chain_db(db, n=4)
    assert verify_db_audit_chain(db) is True


def test_verify_chain_empty_store_is_valid(tmp_path: Path) -> None:
    db = tmp_path / "empty.db"
    engine = create_engine(f"sqlite:///{db.absolute().as_posix()}")
    init_db(engine)
    engine.dispose()
    assert verify_db_audit_chain(db) is True


def test_verify_chain_detects_tamper(tmp_path: Path) -> None:
    db = tmp_path / "tampered.db"
    _seed_chain_db(db, n=3)
    conn = sqlite3.connect(str(db))
    conn.execute("UPDATE core_audit_events SET event_hash = 'sha256:deadbeef'")
    conn.commit()
    conn.close()
    assert verify_db_audit_chain(db) is False


# --- backup -> restore round-trip -------------------------------------------


def test_backup_restore_round_trip_preserves_chain(tmp_path: Path) -> None:
    src = tmp_path / "live.db"
    _seed_chain_db(src, n=5)
    out_dir = tmp_path / "backups"
    assert _cmd_backup(str(src), str(out_dir)) == 0

    backup = next(out_dir.glob("secopent-backup-*.db"))
    restored = tmp_path / "restored.db"
    assert _cmd_restore(str(restored), str(backup)) == 0

    assert verify_db_audit_chain(restored) is True
    assert _count_events(restored) == 5  # every event preserved


def test_restore_creates_rollback_point_for_existing_target(tmp_path: Path) -> None:
    src = tmp_path / "live.db"
    _seed_chain_db(src, n=2)
    out_dir = tmp_path / "backups"
    _cmd_backup(str(src), str(out_dir))
    backup = next(out_dir.glob("secopent-backup-*.db"))

    target = tmp_path / "target.db"
    _seed_chain_db(target, n=1)  # pre-existing live store
    assert _cmd_restore(str(target), str(backup)) == 0
    assert list(tmp_path.glob("target.db.pre-restore-*")), "rollback point created"
    assert _count_events(target) == 2  # now reflects the backup


def test_restore_rejects_corrupt_backup_without_touching_target(tmp_path: Path) -> None:
    src = tmp_path / "live.db"
    _seed_chain_db(src, n=3)
    out_dir = tmp_path / "backups"
    _cmd_backup(str(src), str(out_dir))
    backup = next(out_dir.glob("secopent-backup-*.db"))

    # Corrupt the backup's chain.
    conn = sqlite3.connect(str(backup))
    conn.execute("UPDATE core_audit_events SET previous_hash = 'bad'")
    conn.commit()
    conn.close()

    target = tmp_path / "target.db"
    _seed_chain_db(target, n=1)
    assert _cmd_restore(str(target), str(backup)) == 1
    assert _count_events(target) == 1  # live store untouched


# --- --include-secrets -------------------------------------------------------


def test_backup_include_secrets_requires_source(tmp_path: Path) -> None:
    src = tmp_path / "live.db"
    _seed_chain_db(src, n=1)
    out_dir = tmp_path / "backups"
    assert _cmd_backup(str(src), str(out_dir), include_secrets=True) == 1
    assert not list(out_dir.glob("secrets-*.enc"))


def test_backup_include_secrets_copies_encrypted_store(tmp_path: Path) -> None:
    src = tmp_path / "live.db"
    _seed_chain_db(src, n=1)
    secrets = tmp_path / "secrets.enc"
    secrets.write_bytes(b"\x00encrypted-blob")
    out_dir = tmp_path / "backups"
    assert (
        _cmd_backup(str(src), str(out_dir), include_secrets=True, secrets_path=str(secrets))
        == 0
    )
    copied = next(out_dir.glob("secrets-*.enc"))
    assert copied.read_bytes() == b"\x00encrypted-blob"
