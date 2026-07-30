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

from secopent.__version__ import __version__

__all__ = ["build_parser", "main", "__version__"]


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
    backup.add_argument(
        "--include-secrets",
        action="store_true",
        help="Also copy the encrypted SecretStore into the backup directory.",
    )
    backup.add_argument(
        "--secrets",
        default=None,
        help="Path to the encrypted SecretStore export (required with --include-secrets).",
    )
    restore = subparsers.add_parser(
        "restore",
        help="Restore the SQLite store from a backup (verifies the audit chain).",
    )
    restore.add_argument("--db", required=True, help="Path to the live SQLite database file.")
    restore.add_argument(
        "--from", dest="from_backup", required=True, help="Path to the backup file to restore."
    )
    return parser


def _cmd_version() -> int:
    print(__version__)
    return 0


def _cmd_backup(
    db_path: str, out_dir: str, *, include_secrets: bool = False, secrets_path: str | None = None
) -> int:
    """Back up the SQLite store with a consistent online snapshot (§3.8).

    Uses sqlite3 backup (safe even while the API writes). With
    ``--include-secrets`` the already-encrypted SecretStore export is copied
    alongside the database; the Fernet MASTER KEY is held out-of-band and is
    NEVER written into the backup (so a backup leak does not leak secrets).
    """
    import shutil
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

    if include_secrets:
        if not secrets_path:
            print("error: --include-secrets requires --secrets <encrypted-store-path>")
            print(
                "note: the Fernet master key is held out-of-band and is NEVER "
                "written to the backup"
            )
            return 1
        secrets_src = Path(secrets_path)
        if not secrets_src.exists():
            print(f"error: encrypted secret store not found: {secrets_path}")
            return 1
        secrets_dest = out / f"secrets-{timestamp}.enc"
        shutil.copy2(secrets_src, secrets_dest)
        print(f"backed up encrypted secret store {secrets_src} -> {secrets_dest}")
        print(
            "WARNING: the Fernet master key is NOT in this backup; escrow it "
            "separately (see docs/ops/backup-restore.md)"
        )
    return 0


def _cmd_restore(db_path: str, from_backup: str) -> int:
    """Restore the store from a backup, verifying the audit chain (§3.8 / T8).

    Safe sequence: (1) verify the BACKUP's audit chain before touching the live
    store (a corrupt backup is rejected); (2) snapshot the current store to a
    ``.pre-restore-<ts>`` rollback point; (3) atomically replace; (4) verify the
    restored store's chain and roll back if it fails. The API service must be
    stopped for the duration (the CLI cannot stop a separate process; see the
    runbook).
    """
    import os
    import shutil
    from datetime import datetime
    from pathlib import Path

    from secopent.infrastructure.audit.chain_verify import verify_db_audit_chain

    src = Path(from_backup)
    target = Path(db_path)
    if not src.exists():
        print(f"error: backup not found: {from_backup}")
        return 1
    if not verify_db_audit_chain(src):
        print("error: backup audit chain INVALID; refusing to restore")
        return 1

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    rollback: Path | None = None
    if target.exists():
        rollback = target.with_name(f"{target.name}.pre-restore-{timestamp}")
        shutil.copy2(target, rollback)

    tmp = target.with_name(f"{target.name}.restore-tmp-{timestamp}")
    shutil.copy2(src, tmp)
    os.replace(tmp, target)

    if not verify_db_audit_chain(target):
        print("error: restored db audit chain INVALID; rolling back")
        if rollback is not None:
            os.replace(rollback, target)
        return 1

    print(f"restored {src} -> {target} (audit chain verified)")
    if rollback is not None:
        print(f"rollback point: {rollback}")
    print(
        "note: ensure the API service was stopped during restore "
        "(see docs/ops/backup-restore.md)"
    )
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
        return _cmd_backup(
            args.db,
            args.out,
            include_secrets=args.include_secrets,
            secrets_path=args.secrets,
        )
    if args.command == "restore":
        return _cmd_restore(args.db, args.from_backup)
    parser.print_help()
    return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
