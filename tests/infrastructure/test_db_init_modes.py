"""init_db mode param + SECOPTENT_DB_INIT env (W4-D T1)."""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine, inspect, text

from secopent.infrastructure.db.core_models import CoreBase
from secopent.infrastructure.db.session import init_db


def _engine():  # type: ignore[no-untyped-def]
    return create_engine("sqlite:///:memory:")


def test_always_creates_tables_on_fresh_db() -> None:
    eng = _engine()
    init_db(eng, mode="always")
    assert inspect(eng).has_table("core_projects")


def test_skip_does_not_create_tables() -> None:
    eng = _engine()
    init_db(eng, mode="skip")
    assert not inspect(eng).has_table("core_projects")


def test_auto_creates_tables_on_fresh_db() -> None:
    eng = _engine()
    init_db(eng, mode="auto")
    assert inspect(eng).has_table("core_projects")


def test_auto_skips_create_all_when_tables_exist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    eng = _engine()
    CoreBase.metadata.create_all(eng)  # pre-create -> existing DB
    calls: list[object] = []
    real = CoreBase.metadata.create_all

    def _spy(_self: object, bind: object, **_kw: object) -> None:
        calls.append(bind)
        real(bind)  # type: ignore[operator]

    monkeypatch.setattr(CoreBase.metadata, "create_all", _spy)
    init_db(eng, mode="auto")
    assert calls == []  # existing DB -> create_all skipped (alembic owns schema)


def test_mode_reads_from_env_when_not_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECOPTENT_DB_INIT", "skip")
    eng = _engine()
    init_db(eng)  # no mode arg -> reads SECOPTENT_DB_INIT
    assert not inspect(eng).has_table("core_projects")


def test_auto_stamps_fresh_db_when_flag_set(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("SECOPTENT_DB_STAMP_ON_INIT", "1")
    eng = create_engine(f"sqlite:///{(tmp_path / 't.db').as_posix()}")
    init_db(eng, mode="auto")
    with eng.connect() as conn:
        rows = conn.execute(text("SELECT version_num FROM alembic_version")).fetchall()
    assert len(rows) == 1  # stamped at head (tracked from baseline)


def test_auto_does_not_stamp_when_flag_unset(tmp_path) -> None:  # type: ignore[no-untyped-def]
    eng = create_engine(f"sqlite:///{(tmp_path / 't.db').as_posix()}")
    init_db(eng, mode="auto")
    # create_all does not create alembic_version; stamp skipped (flag unset).
    assert not inspect(eng).has_table("alembic_version")
