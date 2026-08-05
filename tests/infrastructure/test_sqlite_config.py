"""SQLite connection-time PRAGMA configuration (v4 mitigation)."""
from __future__ import annotations

from secopent.infrastructure.db.sqlite import create_sqlite_engine


def test_busy_timeout_is_60_seconds(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """v4 mitigation: high-frequency signed-audit INSERT storm (W3-C) must not
    fail on busy lock. 5s was too short; 60s buys time for the same-tx merge
    (T3) + covers edge cases under heavier load."""
    eng = create_sqlite_engine(tmp_path / "t.db")
    with eng.connect() as conn:
        row = conn.exec_driver_sql("PRAGMA busy_timeout").fetchone()
    assert row is not None
    assert row[0] == 60000
