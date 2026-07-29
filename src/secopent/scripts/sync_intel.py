# src/secopent/scripts/sync_intel.py
"""Intel source sync CLI (P3 §3.4): pull a vuln feed into the local SQLite store.

Usage::

    py -3.12 -m secopent.scripts.sync_intel --source osv --limit 5000 --db secopent.db

Pulls the OSV.dev feed (reachable from CN networks; NVD is not) via
``OsvClient`` and persists each record through
``SqlAlchemyIntelRepository.add_vulnerability``, which keeps the
``core_vulnerabilities_fts`` FTS5 table in sync so ``GET /intel/search``
returns real CVEs afterwards.

The script is a thin dispatcher: ``sync_from_osv`` is the testable core (an
injectable client + session), and ``main`` only wires argparse, the engine,
and schema bootstrap (``init_db`` creates every table + the FTS5 virtual
table). No real network calls happen in the test suite - tests inject a
client backed by ``httpx.MockTransport``.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy.orm import Session

from ..infrastructure.db.session import init_db
from ..infrastructure.db.sqlite import create_sqlite_engine
from ..infrastructure.intel_sources import OsvClient
from ..infrastructure.repositories.sqlalchemy_intel import SqlAlchemyIntelRepository

_DEFAULT_DB = "secopent.db"
_DEFAULT_LIMIT = 100


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secopent.scripts.sync_intel",
        description="Sync a vulnerability intel feed into the local SQLite store.",
    )
    parser.add_argument(
        "--source",
        choices=["osv"],
        default="osv",
        help="Intel source to sync (currently: osv).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=_DEFAULT_LIMIT,
        help="Maximum number of records to persist (default: %(default)s).",
    )
    parser.add_argument(
        "--db",
        default=_DEFAULT_DB,
        help="Path to the SQLite database file (default: %(default)s).",
    )
    return parser


def sync_from_osv(session: Session, client: OsvClient, *, limit: int) -> int:
    """Fetch up to ``limit`` OSV records and persist them. Returns the count.

    The caller owns the transaction (commit/rollback). Persistence keeps the
    FTS5 search index in sync, so a following ``search_fts`` sees the records.
    """
    if limit < 0:
        raise ValueError(f"limit must be >= 0, got {limit}")
    repo = SqlAlchemyIntelRepository(session)
    vulns = client.fetch_incremental(last_modified=None)[:limit]
    for vuln in vulns:
        repo.add_vulnerability(vuln)
    return len(vulns)


def main(argv: list[str] | None = None, *, client: OsvClient | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    engine = create_sqlite_engine(Path(args.db))
    init_db(engine)  # creates all tables + the FTS5 virtual table
    sync_client = client if client is not None else OsvClient()

    with Session(engine) as session:
        try:
            count = sync_from_osv(session, sync_client, limit=args.limit)
            session.commit()
        except Exception as exc:  # noqa: BLE001 - CLI reports any sync failure
            session.rollback()
            print(f"error: sync failed: {exc}")
            return 1

    print(f"synced {count} vulnerabilities from {args.source} -> {args.db}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
