#!/usr/bin/env python
"""Verify a SecOpent backup or restored database (P3 §3.8 / T8).

Recomputes the persisted audit hash chain of a SQLite store and reports whether
it is intact. Use it after a backup (``secopent backup``) or a restore
(``secopent restore``) as an independent integrity check, and in the monthly
restore drill (see docs/ops/backup-restore.md).

Usage:
    python scripts/verify_backup.py <path-to-db>

Exit codes: 0 = audit chain intact, 1 = corrupt/invalid (or unreadable store).
"""
from __future__ import annotations

import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: verify_backup.py <path-to-db>")
        return 2
    db_path = Path(args[0])
    if not db_path.exists():
        print(f"error: db not found: {db_path}")
        return 1

    from secopent.infrastructure.audit.chain_verify import verify_db_audit_chain

    try:
        intact = verify_db_audit_chain(db_path)
    except Exception as exc:  # noqa: BLE001 - report any failure to read/verify
        print(f"error: could not verify {db_path}: {exc}")
        return 1

    if intact:
        print(f"OK: audit chain intact in {db_path}")
        return 0
    print(f"FAIL: audit chain INVALID in {db_path}")
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
