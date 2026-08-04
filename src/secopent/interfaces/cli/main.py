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
import contextlib
import os
import sys
from pathlib import Path

from secopent.__version__ import __version__

__all__ = ["build_parser", "main", "__version__"]


def _chmod_0600(path: Path) -> None:
    """Best-effort 0600 on a sensitive file (POSIX only; no-op elsewhere).

    Backup/restore files contain findings/scope/audit-chain material; the
    encrypted secret store copy contains ciphertext. All deserve 0600 even
    though the parent directory should already be 0700.
    """
    if os.name != "posix":
        return
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


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
    upgrade = subparsers.add_parser(
        "upgrade",
        help="Pull code + reinstall deps + rebuild frontend + migrate DB (run in the repo).",
    )
    upgrade.add_argument(
        "--no-frontend", action="store_true", help="Skip the npm install + build step."
    )
    upgrade.add_argument(
        "--no-migrate", action="store_true", help="Skip `alembic upgrade head`."
    )
    upgrade.add_argument(
        "--dry-run", action="store_true", help="Print the steps without running them."
    )
    vacuum = subparsers.add_parser(
        "vacuum",
        help="VACUUM the SQLite DB to reclaim space (stop the API first).",
    )
    vacuum.add_argument("--db", required=True, help="Path to the SQLite database file.")
    db = subparsers.add_parser(
        "db",
        help="Manage the DB schema via alembic (upgrade/stamp/current).",
    )
    db_sub = db.add_subparsers(dest="db_action", required=True)
    for _action, _help in (
        ("upgrade", "Apply alembic migrations to head (creates schema on a fresh DB)."),
        ("stamp", "Mark an existing schema as being at head (no migration run)."),
        ("current", "Print the current alembic revision."),
    ):
        _p = db_sub.add_parser(_action, help=_help)
        _p.add_argument(
            "--db",
            required=True,
            help="Database URL (postgresql://...) or SQLite path.",
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
    _chmod_0600(dest)
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
        _chmod_0600(secrets_dest)
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
        _chmod_0600(rollback)

    tmp = target.with_name(f"{target.name}.restore-tmp-{timestamp}")
    shutil.copy2(src, tmp)
    os.replace(tmp, target)
    _chmod_0600(target)

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


def _cmd_upgrade(
    *, no_frontend: bool = False, no_migrate: bool = False, dry_run: bool = False
) -> int:
    """Pull code + reinstall deps + rebuild frontend + migrate DB.

    Locates the repo root from the editable install (``secopent.__file__``),
    then runs: ``git pull`` -> ``pip install -e ".[dev]"`` -> (frontend)
    ``npm install && npm run build`` -> (DB) ``alembic upgrade head`` -> ``doctor``.
    Each step's output is streamed; a failing step is reported but does not abort
    subsequent independent steps (so a frontend-only change still migrates DB).

    Always back up the DB before upgrading (see docs/deployment/upgrade.md).
    The service must be restarted after a successful upgrade (the CLI prints a
    reminder; it cannot restart systemd itself).
    """
    import shutil
    import subprocess
    from pathlib import Path

    import secopent

    pkg_file = getattr(secopent, "__file__", None)
    if pkg_file is None:
        print("error: cannot locate secopent package source (editable install required)")
        return 1
    root = Path(pkg_file).resolve().parents[2]
    if not (root / ".git").exists():
        print(f"error: {root} is not a git repo (editable install required for `upgrade`)")
        return 1
    web_dir = root / "src" / "secopent" / "interfaces" / "web"

    def _run(step: str, cmd: list[str], cwd: Path) -> int:
        print(f"\n==> {step}")
        print(f"    cwd: {cwd}")
        print(f"    cmd: {' '.join(cmd)}")
        if dry_run:
            return 0
        return subprocess.call(cmd, cwd=str(cwd))

    print(f"SecOpent upgrade (repo: {root})")
    print("WARNING: back up the DB first (secopent backup --db ... --out ...).")

    py = shutil.which("python3") or shutil.which("python") or "python"
    npm = shutil.which("npm")
    alembic = shutil.which("alembic") or f"{py} -m alembic"

    rc = _run("git pull", ["git", "pull", "--ff-only"], root)
    if rc != 0:
        print("error: git pull failed (resolve local changes / merge conflicts, then re-run)")
        return rc
    _run("pip install (deps)", [py, "-m", "pip", "install", "-e", ".[dev]"], root)

    if not no_frontend and npm and web_dir.exists():
        _run("npm install", [npm, "ci", "--legacy-peer-deps"], web_dir)
        _run("npm run build", [npm, "run", "build"], web_dir)
    elif no_frontend:
        print("\n==> frontend: skipped (--no-frontend)")

    if not no_migrate and (root / "alembic.ini").exists():
        alembic_cmd = alembic.split() if isinstance(alembic, str) else [alembic]
        _run("alembic upgrade head", [*alembic_cmd, "upgrade", "head"], root)
    elif no_migrate:
        print("\n==> migration: skipped (--no-migrate)")

    if not dry_run:
        print("\n==> doctor")
        _cmd_doctor()

    print("\nUpgrade complete. Restart the service:")
    print("    sudo systemctl restart secopent")
    print("(or `docker restart secopent` for container deployments)")
    return 0


def _cmd_vacuum(db_path: str) -> int:
    """VACUUM the SQLite DB to reclaim space (findings + audit chain grow).

    Requires exclusive access (stop the API first, like restore). Folds the WAL
    back into the main file (wal_checkpoint TRUNCATE) then rebuilds the file
    compactly (VACUUM). Run periodically (cron) on long-lived NAS installs.
    """
    import sqlite3
    from pathlib import Path

    src = Path(db_path)
    if not src.exists():
        print(f"error: db not found: {db_path}")
        return 1
    conn = sqlite3.connect(str(src))
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("VACUUM")
        conn.commit()
    finally:
        conn.close()
    print(f"vacuumed {src}")
    print("note: ensure the API service was stopped (exclusive access required)")
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


def _cmd_db(action: str, db_url: str) -> int:
    """Run an alembic action (upgrade/stamp/current) against the DB (W4-D T2).

    Sets ``SECOPTENT_DB_URL`` so ``alembic/env.py`` targets the given DB. A bare
    path (no ``://``) is treated as SQLite. Production runs ``db upgrade``
    before boot; ``db stamp`` marks an existing ``create_all``-bootstrapped DB
    as being at head so subsequent upgrades know the starting point.
    """
    import secopent

    pkg_file = getattr(secopent, "__file__", None)
    if pkg_file is None:
        print("error: cannot locate secopent package source (editable install required)")
        return 1
    ini = Path(pkg_file).resolve().parents[2] / "alembic.ini"
    if not ini.exists():
        print(f"error: alembic.ini not found at {ini}")
        return 1

    url = db_url if "://" in db_url else f"sqlite:///{db_url}"
    saved_url = os.environ.get("SECOPTENT_DB_URL")
    os.environ["SECOPTENT_DB_URL"] = url

    from alembic import command
    from alembic.config import Config

    cfg = Config(str(ini))
    try:
        if action == "upgrade":
            command.upgrade(cfg, "head")
        elif action == "stamp":
            command.stamp(cfg, "head")
        elif action == "current":
            command.current(cfg)
        else:
            print(f"error: unknown db action: {action}")
            return 1
    except Exception as exc:  # noqa: BLE001 - CLI surfaces the alembic failure
        print(f"error: alembic {action} failed: {exc}")
        return 1
    finally:
        # Restore so in-process CLI calls (e.g. tests) don't leak the URL.
        if saved_url is None:
            os.environ.pop("SECOPTENT_DB_URL", None)
        else:
            os.environ["SECOPTENT_DB_URL"] = saved_url
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
    if args.command == "upgrade":
        return _cmd_upgrade(
            no_frontend=args.no_frontend,
            no_migrate=args.no_migrate,
            dry_run=args.dry_run,
        )
    if args.command == "vacuum":
        return _cmd_vacuum(args.db)
    if args.command == "db":
        return _cmd_db(args.db_action, args.db)
    parser.print_help()
    return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
