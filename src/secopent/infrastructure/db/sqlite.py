from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine


def create_sqlite_engine(path: Path) -> Engine:
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False, "timeout": 5.0},
        future=True,
        # NullPool: each thread (request handler + background executor) gets
        # its own connection, avoiding StaticPool's single-shared-connection
        # contention. SQLite WAL handles the concurrency at the file level.
        poolclass=None,  # SQLAlchemy defaults to QueuePool for file-based SQLite
        pool_size=5,
        max_overflow=10,
    )

    @event.listens_for(engine, "connect")
    def configure(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        # §3.5 performance: synchronous=NORMAL is durable under WAL (only the
        # final commit fsync is skipped) and much faster than FULL; cap the WAL
        # file so a long-running assessment cannot grow it without bound.
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA journal_size_limit=67108864")
        cursor.close()

    return engine
