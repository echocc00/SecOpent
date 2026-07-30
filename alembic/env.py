"""Alembic migration environment (T15 / cross-cutting §④).

Targets the shared ``CoreBase.metadata`` (importing ``secopent.infrastructure.
db.session`` registers every ORM model) and the URL from ``SECOPTENT_DB_URL``
(SQLite or PostgreSQL). The SQLite-only ``core_vulnerabilities_fts`` FTS5 virtual
table is NOT in the metadata - it is created by ``init_db`` and needs a PG
tsvector equivalent for PostgreSQL full-text search (tracked separately).
"""
from __future__ import annotations

from logging.config import fileConfig

from sqlalchemy import create_engine, pool

from alembic import context
from secopent.infrastructure.db.engine import configured_database_url
from secopent.infrastructure.db.session import CoreBase

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = CoreBase.metadata


def _database_url() -> str:
    return (
        configured_database_url()
        or config.get_main_option("sqlalchemy.url")
        or "sqlite:///secopent.db"
    )


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(_database_url(), poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
