# src/secopent/infrastructure/db/session.py
"""Database session factory + FastAPI dependency (Phase A P1, W1).

Binds a SQLAlchemy engine to a session factory and exposes a request-scoped
session dependency for the FastAPI routers. ``init_db`` creates all tables
(importing every ORM model module so each registers on ``CoreBase.metadata``).
"""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

# Import every ORM model module so all tables register on CoreBase.metadata.
from . import (  # noqa: F401
    asset_models,
    catalog_models,
    core_models,
    finding_models,
    intel_models,
    job_models,
    report_models,
    update_models,
)
from .core_models import CoreBase


def init_db(engine: Engine) -> None:
    """Create all tables on the engine."""
    CoreBase.metadata.create_all(engine)


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
