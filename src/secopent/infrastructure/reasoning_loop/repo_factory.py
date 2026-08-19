# src/secopent/infrastructure/reasoning_loop/repo_factory.py
"""Composition factory: pick SQL vs InMemory loop repos (v0.7.8 Task 3).

Selects the persistence backend for the ReasoningLoop state/step repositories
at the composition root:

- a real ``Database`` (SQL) -> the SQLAlchemy-backed repos (``sqlalchemy_state.py``);
- ``None`` (no DB, dev/tests) -> the in-memory stores.

The discriminator is deliberately the least-coupled possible: a ``Database`` is
a SQL container (it wraps a SQLAlchemy engine and produces ``Session``s), so
"not None" means SQL. This keeps tests trivially controllable (pass ``None`` for
in-memory, a real ``Database`` for SQL) without reaching into ``Database``'s
private internals for an is-SQL flag.

Session lifecycle: the SQLAlchemy repos hold one ``Session`` for their lifetime
(``merge``-based writes, no commit). The factory borrows a session via
``Database.open_session()`` (the request-scoped ``Database.session()`` generator
is a FastAPI dependency and cannot be used outside a request). The caller owns
that session and is responsible for committing/opening a fresh one across
request boundaries; a long-running singleton should NOT reuse a single session
for its whole lifetime (see ``database_recorder.py``).
"""
from __future__ import annotations

from ...application.ports.loop_state import LoopStateRepository
from ...application.ports.loop_step import LoopStepRepository
from ...application.reasoning_loop.in_memory_state import (
    InMemoryLoopStateRepository,
    InMemoryLoopStepRepository,
)
from ..db.session import Database
from .sqlalchemy_state import (
    SqlAlchemyLoopStateRepository,
    SqlAlchemyLoopStepRepository,
)


def create_loop_state_repo(db: Database | None) -> LoopStateRepository:
    """Return the SQL state repo when a real Database is present, else InMemory.

    ``db is not None`` is the discriminator: a ``Database`` is by construction a
    SQL-capable container (it owns a SQLAlchemy engine + session factory), so a
    non-``None`` value means the caller has a real backend to persist against.
    """
    if db is None:
        return InMemoryLoopStateRepository()
    return SqlAlchemyLoopStateRepository(db.open_session())


def create_loop_step_repo(db: Database | None) -> LoopStepRepository:
    """Return the SQL step repo when a real Database is present, else InMemory."""
    if db is None:
        return InMemoryLoopStepRepository()
    return SqlAlchemyLoopStepRepository(db.open_session())
