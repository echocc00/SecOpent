# src/secopent/infrastructure/audit/chain_verify.py
"""Verify the persisted audit hash chain of a SQLite store (P3 §3.8 / T8).

Used by ``secopent restore`` and ``scripts/verify_backup.py`` to confirm a
backup or freshly-restored database is tamper-free: every audit event is
reloaded (a hash-faithful round-trip via ``SqlAlchemyAuditRepository``) and the
chain is recomputed with the deterministic domain rule
``AuditEvent.verify_chain``. The Ed25519 event signatures live in the in-memory
``AuditChain``; the database stores the hash commitments, so hash-chain
integrity is what a file-level backup/restore can and does verify.

Lives in infrastructure (it opens a SQLAlchemy engine); the domain rule it
delegates to stays framework-free.
"""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from secopent.domain.audit.models import AuditEvent
from secopent.infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAuditRepository,
)


def verify_db_audit_chain(db_path: str | Path) -> bool:
    """Return True iff the audit hash chain in ``db_path`` is intact.

    An empty chain (no audit events yet) is trivially valid. A corrupted or
    reordered event - any break in ``previous_hash`` linkage or a recomputed
    ``event_hash`` mismatch - yields False.
    """
    url = f"sqlite:///{Path(db_path).absolute().as_posix()}"
    engine = create_engine(url)
    try:
        session = sessionmaker(bind=engine)()
        try:
            events = SqlAlchemyAuditRepository(session).list_events()
        finally:
            session.close()
    finally:
        engine.dispose()
    return AuditEvent.verify_chain(events)
