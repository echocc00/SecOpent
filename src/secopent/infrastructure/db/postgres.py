# src/secopent/infrastructure/db/postgres.py
"""PostgreSQL engine factory (M5 Task 9, §13 Repository contract portability).

The M0 Repository abstraction (SQLAlchemy ORM over ``CoreBase``) is
backend-agnostic: the same models and repositories run on SQLite (dev/test) and
PostgreSQL (production). This factory builds a PG engine; the contract test runs
the identical repository round-trips against it (skipped when no PG is reachable)
to prove the switch needs no domain/application refactor (FTS5 -> PG full-text is
the only SQLite-specific concern, isolated in the intel repository).
"""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine


def create_postgres_engine(dsn: str) -> Engine:
    """Create a PostgreSQL engine from a DSN (e.g. postgresql+psycopg://...)."""
    return create_engine(dsn, future=True, pool_pre_ping=True)
