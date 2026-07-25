from __future__ import annotations
from pathlib import Path
from sqlalchemy import text
from secopent.infrastructure.db.sqlite import create_sqlite_engine


def test_sqlite_enables_wal_and_foreign_keys(tmp_path: Path) -> None:
    engine = create_sqlite_engine(tmp_path / "secopent.db")
    with engine.connect() as connection:
        assert connection.execute(text("PRAGMA journal_mode")).scalar_one().lower() == "wal"
        assert connection.execute(text("PRAGMA foreign_keys")).scalar_one() == 1
        assert connection.execute(text("PRAGMA busy_timeout")).scalar_one() == 5000


def test_sqlite_engine_is_reusable(tmp_path: Path) -> None:
    engine = create_sqlite_engine(tmp_path / "secopent.db")
    with engine.connect() as c1:
        c1.execute(text("CREATE TABLE t (x INTEGER)"))
        c1.commit()
    with engine.connect() as c2:
        c2.execute(text("INSERT INTO t VALUES (1)"))
        c2.commit()
    with engine.connect() as c3:
        assert c3.execute(text("SELECT x FROM t")).scalar_one() == 1
