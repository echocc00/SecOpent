# tests/infrastructure/test_db_engine.py
"""Tests for the SECOPTENT_DB_URL engine factory (T15 / cross-cutting §④)."""
from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import text

from secopent.infrastructure.db.engine import (
    DB_URL_ENV,
    configured_database_url,
    create_engine_from_url,
    is_postgres_url,
)


def test_configured_database_url_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(DB_URL_ENV, "postgresql+psycopg://u:p@localhost:5432/secopent")
    assert configured_database_url() == "postgresql+psycopg://u:p@localhost:5432/secopent"


def test_configured_database_url_none_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(DB_URL_ENV, raising=False)
    assert configured_database_url() is None


def test_is_postgres_url() -> None:
    assert is_postgres_url("postgresql://u:p@h/db") is True
    assert is_postgres_url("postgresql+psycopg://u:p@h/db") is True
    assert is_postgres_url("sqlite:///secopent.db") is False
    assert is_postgres_url("sqlite:///:memory:") is False


def test_create_engine_from_url_sqlite_round_trip(tmp_path: Path) -> None:
    engine = create_engine_from_url(f"sqlite:///{tmp_path / 'x.db'}")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)"))
        conn.execute(text("INSERT INTO t (v) VALUES ('hello')"))
    with engine.connect() as conn:
        assert conn.execute(text("SELECT v FROM t")).scalar_one() == "hello"
    engine.dispose()


def test_create_engine_from_url_postgres_dialect() -> None:
    # No connection is opened at engine creation; just verify the dialect.
    engine = create_engine_from_url("postgresql+psycopg://u:p@localhost:5432/secopent")
    assert engine.dialect.name == "postgresql"
    engine.dispose()


def test_create_app_honours_secopent_db_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from secopent.interfaces.api.main import create_app

    db_file = tmp_path / "configured.db"
    monkeypatch.setenv(DB_URL_ENV, f"sqlite:///{db_file}")
    app = create_app()
    assert db_file.name in str(app.state.db._engine.url)  # noqa: SLF001 - test seam
