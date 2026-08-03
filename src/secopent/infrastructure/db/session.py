# src/secopent/infrastructure/db/session.py
"""Database session factory + FastAPI dependency (Phase A P1, W1).

Binds a SQLAlchemy engine to a session factory and exposes a request-scoped
session dependency for the FastAPI routers. ``init_db`` creates all tables
(importing every ORM model module so each registers on ``CoreBase.metadata``).
"""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

# Import every ORM model module so all tables register on CoreBase.metadata.
from . import (  # noqa: F401
    appmodel_models,
    asset_models,
    case_models,
    catalog_models,
    core_models,
    evidence_models,
    finding_models,
    intel_models,
    job_models,
    report_models,
    update_models,
)
from .core_models import CoreBase


def init_db(engine: Engine) -> None:
    """Create all tables on the engine.

    Also creates the ``core_vulnerabilities_fts`` FTS5 virtual table used by
    the intel search endpoint (SQLite only). SQLAlchemy 2.0 does not model FTS5
    virtual tables declaratively, so it is issued as raw DDL here (idempotent
    via ``IF NOT EXISTS``). On PostgreSQL the FTS5 DDL is skipped (PG uses
    tsvector; the intel search endpoint falls back to LIKE queries).
    """
    CoreBase.metadata.create_all(engine)
    if engine.dialect.name == "sqlite":
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS core_vulnerabilities_fts "
                    "USING fts5(canonical_id UNINDEXED, cve, description, cwe)"
                )
            )


class Database:
    """Holds a session factory and yields request-scoped sessions."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        self._factory = sessionmaker(bind=engine, expire_on_commit=False)
        init_db(engine)

    def session(self) -> Iterator[Session]:
        """FastAPI dependency: yield a session, commit on success, rollback on error."""
        session = self._factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def open_session(self) -> Session:
        """Open a standalone session; the caller owns commit/close.

        Used by long-lived streams (SSE, P3 §3.5) that poll outside a single
        request's dependency scope - each poll opens and closes a short-lived
        session rather than holding one for the stream's whole lifetime.
        """
        return self._factory()
