"""secopent db CLI (W4-D T2)."""
from __future__ import annotations

from sqlalchemy import create_engine, inspect, text

from secopent.infrastructure.db.core_models import CoreBase
from secopent.interfaces.cli.main import main


def _url(tmp_path, name: str = "t.db") -> str:  # type: ignore[no-untyped-def]
    return f"sqlite:///{(tmp_path / name).as_posix()}"


def test_db_upgrade_creates_schema(tmp_path) -> None:  # type: ignore[no-untyped-def]
    url = _url(tmp_path)
    rc = main(["db", "upgrade", "--db", url])
    assert rc == 0
    eng = create_engine(url)
    assert inspect(eng).has_table("core_projects")
    assert inspect(eng).has_table("alembic_version")


def test_db_stamp_marks_existing_schema(tmp_path) -> None:  # type: ignore[no-untyped-def]
    url = _url(tmp_path)
    eng = create_engine(url)
    CoreBase.metadata.create_all(eng)  # existing DB, not yet alembic-tracked
    rc = main(["db", "stamp", "--db", url])
    assert rc == 0
    with eng.connect() as conn:
        rows = conn.execute(text("SELECT version_num FROM alembic_version")).fetchall()
    assert len(rows) == 1


def test_db_current_after_upgrade(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    url = _url(tmp_path)
    main(["db", "upgrade", "--db", url])
    rc = main(["db", "current", "--db", url])
    assert rc == 0
    captured = capsys.readouterr()
    assert "ad674b51adca" in (captured.out + captured.err)  # baseline revision
