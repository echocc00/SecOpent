# src/secopent/interfaces/cli/main.py
"""Typer-style CLI (built on argparse; typer is not a dependency) (§13).

The CLI is a thin dispatcher over the Application Services - it owns no business
logic. It resolves nothing relative to the current directory, so it runs from
any CWD. Commands return a process exit code (0 = success).

Implemented commands (representative core; the full command set wraps the same
services): ``version``, ``doctor`` (health check of the deterministic core).
"""
from __future__ import annotations

import argparse
import sys

__version__ = "0.1.0-dev"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secopent",
        description="Catalog-driven Agent-native authorized pentest workbench.",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("version", help="Print the version and exit.")
    subparsers.add_parser("doctor", help="Health-check the deterministic core.")
    backup = subparsers.add_parser(
        "backup", help="Back up the SQLite store (consistent snapshot)."
    )
    backup.add_argument("--db", required=True, help="Path to the SQLite database file.")
    backup.add_argument(
        "--out", required=True, help="Directory to write the backup into."
    )
    return parser


def _cmd_version() -> int:
    print(__version__)
    return 0


def _cmd_backup(db_path: str, out_dir: str) -> int:
    """Back up the SQLite store with a consistent online snapshot (§3.8).

    Uses sqlite3 backup (safe even while the API writes). The SecretStore's
    in-memory backend has nothing persistent to export; its references are
    covered by the audit chain in the database.
    """
    import sqlite3
    from datetime import datetime
    from pathlib import Path

    src = Path(db_path)
    if not src.exists():
        print(f"error: db not found: {db_path}")
        return 1
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = out / f"secopent-backup-{timestamp}.db"
    src_conn = sqlite3.connect(str(src))
    dest_conn = sqlite3.connect(str(dest))
    try:
        src_conn.backup(dest_conn)
    finally:
        dest_conn.close()
        src_conn.close()
    print(f"backed up {src} -> {dest}")
    return 0


def _cmd_doctor() -> int:
    """Verify the deterministic core imports and basic invariants hold."""
    try:
        from secopent.domain.policy.engine import evaluate  # noqa: F401
        from secopent.domain.scope.models import ScopeDraft  # noqa: F401
        from secopent.domain.verification.registry import default_registry

        registry = default_registry()
        assert len(registry.vuln_types()) == 14
    except Exception as exc:  # noqa: BLE001 - doctor reports any core failure
        print(f"unhealthy: {exc}")
        return 1
    print("ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "version":
        return _cmd_version()
    if args.command == "doctor":
        return _cmd_doctor()
    if args.command == "backup":
        return _cmd_backup(args.db, args.out)
    parser.print_help()
    return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
