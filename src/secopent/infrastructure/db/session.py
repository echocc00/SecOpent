# src/secopent/infrastructure/db/session.py
"""Database session factory + FastAPI dependency (Phase A P1, W1).

Binds a SQLAlchemy engine to a session factory and exposes a request-scoped
session dependency for the FastAPI routers. ``init_db`` creates all tables on
fresh databases (importing every ORM model module so each registers on
``CoreBase.metadata``); existing databases are left to alembic (W4-D).
"""
from __future__ import annotations

import logging
import os
from collections.abc import Iterator

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

# Import every ORM model module so all tables register on CoreBase.metadata.
from . import (  # noqa: F401
    appmodel_models,
    asset_models,
    case_models,
    catalog_models,
    confirmed_finding_models,
    core_models,
    evidence_models,
    finding_models,
    intel_models,
    job_models,
    outbox_models,
    report_models,
    signed_audit_models,
    update_models,
)
from .core_models import CoreBase

_logger = logging.getLogger(__name__)


def init_db(engine: Engine, *, mode: str | None = None) -> None:
    """Create tables + FTS on the engine per the init ``mode`` (W4-D).

    Modes (``SECOPTENT_DB_INIT`` env, default ``auto``):
    - ``always``: unconditionally ``create_all`` (legacy behavior; tests).
    - ``auto``: ``create_all`` only on fresh DBs (no ``core_projects``); on
      existing DBs schema is alembic-managed (``secopent db upgrade``), so
      ``create_all`` is skipped to avoid racing migrations.
    - ``skip``: do nothing (operator runs alembic out-of-band).

    Also creates the ``core_vulnerabilities_fts`` FTS5 virtual table used by
    the intel search endpoint (SQLite only). It is not in ``CoreBase.metadata``
    (SQLAlchemy 2.0 does not model FTS5 declaratively), so it is issued as raw
    DDL here, idempotent via ``IF NOT EXISTS``. On PostgreSQL the FTS5 DDL is
    skipped (PG uses tsvector; the intel search endpoint falls back to LIKE).
    """
    resolved = mode or os.environ.get("SECOPTENT_DB_INIT", "auto")
    if resolved == "skip":
        return
    create_tables = resolved == "always" or not inspect(engine).has_table(
        "core_projects"
    )
    if create_tables:
        CoreBase.metadata.create_all(engine)
        if os.environ.get("SECOPTENT_DB_STAMP_ON_INIT") == "1":
            _stamp_head(engine)
    elif not inspect(engine).has_table("alembic_version"):
        # v0.5.1 F4 (NAS incident): a pre-alembic DB (v0.2.x, tables created via
        # create_all) has no alembic_version row, so `alembic upgrade head` would
        # re-run the baseline migration and fail with "table already exists".
        # Best-effort: stamp it at the BASELINE (not head - the legacy schema is
        # baseline-equivalent but lacks post-baseline tables like core_audit_outbox),
        # so the operator's `secopent db upgrade` applies only the deltas.
        _logger.info(
            "existing DB has no alembic_version; auto-stamping baseline %s - "
            "run `secopent db upgrade` to apply delta migrations "
            "(e.g. core_audit_outbox)",
            BASELINE_REVISION,
        )
        _stamp_baseline(engine)
    if engine.dialect.name == "sqlite":
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS core_vulnerabilities_fts "
                    "USING fts5(canonical_id UNINDEXED, cve, description, cwe)"
                )
            )


# The alembic baseline revision (hand-written, created in W4-D). Existing
# pre-alembic DBs are stamped here so upgrades only apply delta migrations.
BASELINE_REVISION = "ad674b51adca"


def _stamp(engine: Engine, revision: str) -> None:
    """Best-effort: stamp the DB at an alembic revision (W4-D T3 / v0.5.1 F4).

    A ``create_all``-bootstrapped DB has the schema but no ``alembic_version``
    row; without it, a later ``alembic upgrade`` can't tell the DB is already
    migrated. Stamping records the revision. Failures are swallowed (alembic/
    ini missing, or the baseline is stale) - boot must not break; the operator
    can ``secopent db stamp`` manually.
    """
    try:
        from pathlib import Path

        import secopent
        from alembic import command
        from alembic.config import Config

        ini = Path(secopent.__file__).resolve().parents[2] / "alembic.ini"
        if not ini.exists():
            return
        saved_url = os.environ.get("SECOPTENT_DB_URL")
        os.environ["SECOPTENT_DB_URL"] = str(engine.url)
        try:
            cfg = Config(str(ini))
            command.stamp(cfg, revision)
        finally:
            if saved_url is None:
                os.environ.pop("SECOPTENT_DB_URL", None)
            else:
                os.environ["SECOPTENT_DB_URL"] = saved_url
    except Exception:  # noqa: BLE001 - best-effort stamp; boot must not break
        pass


def _stamp_head(engine: Engine) -> None:
    """Stamp at head (fresh create_all DBs already carry every table)."""
    _stamp(engine, "head")


def _stamp_baseline(engine: Engine) -> None:
    """Stamp at the baseline (legacy v0.2.x DBs are baseline-equivalent)."""
    _stamp(engine, BASELINE_REVISION)


class UnitOfWork:
    """Explicit transaction boundary: one UoW = one session = one commit point.

    Commits on clean exit, rolls back on exception, and always closes the
    session. Background/batch work (the assessment daemon, the outbox worker)
    uses one UoW per run plus explicit ``commit()`` calls at phase boundaries,
    so the SQLite WAL write lock is never held across the multi-minute scan
    phases (v4 root cause; v0.3.0 T3).
    """

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory
        self._session: Session | None = None

    def __enter__(self) -> UnitOfWork:
        self._session = self._factory()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        session = self._session
        assert session is not None, "UnitOfWork exited without entering"
        try:
            if exc_type is None:
                session.commit()
            else:
                session.rollback()
        finally:
            session.close()
            self._session = None

    @property
    def session(self) -> Session:
        if self._session is None:
            raise RuntimeError("UnitOfWork used outside its context block")
        return self._session

    def commit(self) -> None:
        """Explicit phase commit; the session stays open for the next phase."""
        self.session.commit()


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

    def unit_of_work(self) -> UnitOfWork:
        """Explicit transaction boundary for background/batch work.

        Request handlers use the ``session()`` dependency instead; this is
        for code paths that outlive a single request (the assessment daemon,
        the outbox worker). Use as ``with db.unit_of_work() as uow: ...``.
        """
        return UnitOfWork(self._factory)
