# src/secopent/infrastructure/db/engine.py
"""Database engine factory: SQLite (default) or PostgreSQL via SECOPTENT_DB_URL.

T15 / cross-cutting §④. The single source of truth for which database the app
binds to:

- ``SECOPTENT_DB_URL`` unset  -> a SQLite engine (dev/test keep their temp DB).
- ``sqlite:///path``          -> the hardened SQLite engine (WAL, FK, busy timeout).
- ``postgresql[+driver]://…`` -> a PostgreSQL engine (connection-pool pre-ping).

``Database``/``init_db`` are engine-agnostic; the relational schema is identical
across both backends (the SQLite-only ``core_vulnerabilities_fts`` FTS5 virtual
table is created by ``init_db`` and needs a PG tsvector equivalent for PG
full-text search - tracked separately).
"""
from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

from .sqlite import create_sqlite_engine

DB_URL_ENV = "SECOPTENT_DB_URL"
DEFAULT_SQLITE_PATH = "secopent.db"

_PG_PREFIXES = ("postgresql://", "postgresql+")


def configured_database_url() -> str | None:
    """The configured database URL, or None to use the caller's default."""
    url = os.environ.get(DB_URL_ENV)
    return url or None


def is_postgres_url(url: str) -> bool:
    return url.startswith(_PG_PREFIXES)


def create_engine_from_url(url: str) -> Engine:
    """Create an engine for a SQLite or PostgreSQL URL."""
    if is_postgres_url(url):
        # pool_pre_ping recycles stale connections (PG idle timeouts); sized for
        # a single-instance deployment.
        return create_engine(
            url, pool_pre_ping=True, pool_size=5, max_overflow=10, future=True
        )
    path = url.removeprefix("sqlite:///")
    return create_sqlite_engine(Path(path))
