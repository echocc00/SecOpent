"""init_db auto-stamp for pre-alembic DBs (v0.5.1 F4).

A v0.2.x DB was bootstrapped with ``create_all`` (tables present, no
``alembic_version`` row), so ``alembic upgrade head`` would re-run the
baseline migration and fail with "table already exists". F4 stamps such a DB
at the BASELINE revision on boot, so the operator's ``secopent db upgrade``
applies only the delta migrations (e.g. ``core_audit_outbox``).
"""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import text
from sqlalchemy.orm import Session

from secopent.infrastructure.db.core_models import CoreBase
from secopent.infrastructure.db.session import init_db
from secopent.infrastructure.db.sqlite import create_sqlite_engine


def _version(engine) -> str | None:  # type: ignore[no-untyped-def]
    with Session(engine) as session:
        return session.execute(text("SELECT version_num FROM alembic_version")).scalar()


def test_init_db_stamps_legacy_db_to_baseline(tmp_path: Path) -> None:
    engine = create_sqlite_engine(tmp_path / "legacy.db")
    # Simulate a v0.2.x DB: baseline tables via create_all, no alembic_version,
    # AND no post-baseline tables (core_audit_outbox came later).
    CoreBase.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE core_audit_outbox"))

    init_db(engine, mode="auto")  # F4: auto-stamp to baseline

    assert _version(engine) == "ad674b51adca"


def test_upgrade_after_autostamp_applies_only_deltas(tmp_path: Path) -> None:
    """The full operator flow: F4 stamp -> `secopent db upgrade` -> outbox table."""
    from secopent.interfaces.cli.main import main

    engine = create_sqlite_engine(tmp_path / "legacy.db")
    CoreBase.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE core_audit_outbox"))

    init_db(engine, mode="auto")  # F4
    assert _version(engine) == "ad674b51adca"

    url = f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}"
    assert main(["db", "upgrade", "--db", url]) == 0

    assert _version(engine) == "bd0a1c2e3f40"  # head = baseline + outbox + control + grants
    with Session(engine) as session:
        outbox = session.execute(
            text(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='core_audit_outbox'"
            )
        ).first()
    assert outbox is not None


def test_init_db_does_not_repeat_stamp(tmp_path: Path) -> None:
    """A second boot with an already-versioned DB must not re-stamp."""
    engine = create_sqlite_engine(tmp_path / "stamped.db")
    CoreBase.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE core_audit_outbox"))

    init_db(engine, mode="auto")
    init_db(engine, mode="auto")  # idempotent: version row already present

    assert _version(engine) == "ad674b51adca"


def test_db_upgrade_cli_autostamps_legacy_db(tmp_path: Path) -> None:
    """The documented stop-then-migrate flow: `secopent db upgrade` on a legacy
    v0.2.x DB auto-stamps the baseline and applies the deltas - no manual
    stamp step needed (v0.5.1 F4 covers the pre-boot CLI path too)."""
    from secopent.interfaces.cli.main import main

    engine = create_sqlite_engine(tmp_path / "legacy.db")
    CoreBase.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE core_audit_outbox"))

    url = f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}"
    assert main(["db", "upgrade", "--db", url]) == 0

    assert _version(engine) == "bd0a1c2e3f40"  # baseline + outbox + control + grants = head
    with Session(engine) as session:
        outbox = session.execute(
            text(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='core_audit_outbox'"
            )
        ).first()
    assert outbox is not None