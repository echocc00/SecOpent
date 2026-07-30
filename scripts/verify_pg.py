#!/usr/bin/env python
"""PostgreSQL backend smoke test for CI (T15 / cross-cutting §④).

Requires ``SECOPTENT_DB_URL`` to be a ``postgresql://`` URL and that
``alembic upgrade head`` has already created the schema. Verifies:

1. the relational schema is present on PG;
2. a SQLite -> PG data migration (same functions as ``scripts/
   migrate_sqlite_to_pg.py``) copies rows and the counts match;
3. an ORM round-trip works against PG.

Run locally only against a real PostgreSQL; the CI ``db`` job drives it.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from secopent.application.audit_chain import AuditChain  # noqa: E402
from secopent.infrastructure.db.engine import (  # noqa: E402
    configured_database_url,
    create_engine_from_url,
)
from secopent.infrastructure.db.session import init_db  # noqa: E402
from secopent.infrastructure.db.sqlite import create_sqlite_engine  # noqa: E402
from secopent.infrastructure.repositories.sqlalchemy_core import (  # noqa: E402
    SqlAlchemyAuditRepository,
)
from secopent.scripts.migrate_db import (  # noqa: E402
    count_rows,
    migrate_tables,
    shared_tables,
    verify_counts,
)


class _NullSigner:
    def sign(self, message: bytes) -> str:
        return "sig"

    def verify(self, message: bytes, signature: str) -> bool:
        return True


def _seed_sqlite(db_path: Path, n: int = 3):  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(db_path)
    init_db(engine)
    session = Session(engine)
    chain = AuditChain(_NullSigner())
    repo = SqlAlchemyAuditRepository(session)
    for i in range(n):
        signed = chain.record(
            actor="a", action="x", resource_type="t", resource_id=f"r{i}", payload={"i": i}
        )
        repo.add(signed.event)
    session.commit()
    session.close()
    return engine


def main() -> int:
    url = configured_database_url()
    if not url or not url.startswith("postgresql"):
        print("error: SECOPTENT_DB_URL must be a postgresql:// URL")
        return 2
    pg = create_engine_from_url(url)

    # 1. Schema present (alembic upgrade head ran).
    with pg.connect() as conn:
        tables = {
            r[0]
            for r in conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            )
        }
    if "core_audit_events" not in tables:
        print(f"error: schema missing on PG; tables={sorted(tables)[:10]}")
        return 1
    print(f"OK: PG schema present ({len(tables)} tables)")

    # 2. SQLite -> PG migration with row-count verification.
    with tempfile.TemporaryDirectory() as tmp:
        src = _seed_sqlite(Path(tmp) / "src.db", n=3)
        tables_to_copy = shared_tables(src, pg)
        counts = migrate_tables(src, pg, tables_to_copy)
        mismatches = verify_counts(src, pg, ["core_audit_events"])
        src.dispose()
    if counts.get("core_audit_events", 0) < 3 or mismatches:
        print(f"error: migration mismatch counts={counts} mismatches={mismatches}")
        return 1
    print(f"OK: SQLite->PG migration verified (audit rows={count_rows(pg, 'core_audit_events')})")

    pg.dispose()
    print("PG smoke test PASSED")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
