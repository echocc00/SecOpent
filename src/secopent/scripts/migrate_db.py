# src/secopent/scripts/migrate_db.py
"""Migrate data from a SQLite store to another database (T15 / cross-cutting §④).

Copies every row of every shared core table from a source SQLite database into a
destination database (PostgreSQL, or another SQLite for verification), then
re-checks row counts table-by-table. The destination schema must already exist
(run ``alembic upgrade head`` for PostgreSQL, or ``init_db`` for SQLite).

Run via the wrapper ``scripts/migrate_sqlite_to_pg.py`` or directly:
    py -3.12 -m secopent.scripts.migrate_db --source secopent.db \
        --dest "postgresql+psycopg://user:pass@host:5432/secopent"
"""
from __future__ import annotations

import argparse

from sqlalchemy import MetaData, create_engine, func, inspect, select
from sqlalchemy.engine import Engine

# Importing the session module registers every ORM model on CoreBase.metadata.
from secopent.infrastructure.db import session as _db_session  # noqa: F401
from secopent.infrastructure.db.core_models import CoreBase
from secopent.infrastructure.db.engine import create_engine_from_url

_SKIP_TABLES = frozenset({"alembic_version", "spatial_ref_sys"})


def _engine(url_or_path: str) -> Engine:
    return create_engine(url_or_path if "://" in url_or_path else f"sqlite:///{url_or_path}")


def shared_tables(source: Engine, dest: Engine) -> list[str]:
    """Migrate only the real ORM tables present in both stores.

    Intersecting with ``CoreBase.metadata`` excludes SQLite FTS5 shadow tables
    (``*_content``/``*_data``/``*_config``/... - copying them row-by-row corrupts
    the virtual table) and migration bookkeeping (``alembic_version``).
    """
    real_tables = set(CoreBase.metadata.tables.keys())
    src_tables = set(inspect(source).get_table_names())
    dst_tables = set(inspect(dest).get_table_names())
    return sorted((src_tables & dst_tables & real_tables) - _SKIP_TABLES)


def _reflect(engine: Engine) -> MetaData:
    meta = MetaData()
    meta.reflect(bind=engine)
    return meta


def migrate_tables(source: Engine, dest: Engine, tables: list[str]) -> dict[str, int]:
    """Copy all rows of each table from source to dest; return per-table counts."""
    src_meta = _reflect(source)
    dst_meta = _reflect(dest)
    counts: dict[str, int] = {}
    for name in tables:
        src_table = src_meta.tables[name]
        dst_table = dst_meta.tables[name]
        with source.connect() as conn:
            rows = [dict(row) for row in conn.execute(select(src_table)).mappings()]
        if rows:
            with dest.begin() as conn:
                conn.execute(dst_table.insert(), rows)
        counts[name] = len(rows)
    return counts


def count_rows(engine: Engine, table: str) -> int:
    meta = _reflect(engine)
    with engine.connect() as conn:
        return int(
            conn.execute(select(func.count()).select_from(meta.tables[table])).scalar_one()
        )


def verify_counts(source: Engine, dest: Engine, tables: list[str]) -> list[str]:
    """Return 'table: source=N dest=M' for any table whose counts differ."""
    return [
        f"{name}: source={count_rows(source, name)} dest={count_rows(dest, name)}"
        for name in tables
        if count_rows(source, name) != count_rows(dest, name)
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Migrate a SecOpent SQLite store to another DB.")
    parser.add_argument("--source", required=True, help="source SQLite path or URL")
    parser.add_argument("--dest", required=True, help="destination URL (postgresql:// or sqlite:///)")
    args = parser.parse_args(argv)

    source = _engine(args.source)
    dest = create_engine_from_url(args.dest)
    tables = shared_tables(source, dest)
    if not tables:
        print("error: no shared tables (create the destination schema first)")
        return 1

    counts = migrate_tables(source, dest, tables)
    mismatches = verify_counts(source, dest, tables)
    print(f"migrated {sum(counts.values())} rows across {len(counts)} tables")
    if mismatches:
        print("ERROR: row-count mismatches after migration:")
        for mismatch in mismatches:
            print(f"  - {mismatch}")
        return 1
    print("OK: row counts match table-by-table")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
