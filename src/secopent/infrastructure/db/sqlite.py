from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine

from ...domain.common.errors import DomainError

# Filesystem types that break SQLite WAL: file locks are unreliable over them,
# so the DB will silently corrupt under concurrent access. tmpfs/overlay are
# NOT listed - they are local (just not disk-backed) and safe for SQLite.
_NETWORK_FS_TYPES = frozenset(
    {
        "nfs",
        "nfs4",
        "cifs",
        "smb",
        "smb2",
        "smb3",
        "fuse.sshfs",
        "fuse.glusterfs",
        "fuse.gvfs",
        "fuse.s3fs",
    }
)


class NetworkFilesystemError(DomainError):
    """SQLite cannot be used on a network filesystem (WAL corruption risk)."""


def _filesystem_type(path: Path) -> str:
    """The filesystem type backing ``path`` (Linux /proc/mounts; '' if unknown).

    Matches the longest mount-point prefix so a path under /mnt/nfs/data is
    correctly attributed to nfs, not the root filesystem. Non-Linux platforms
    return '' (the NFS guard is a no-op there - Windows/macOS don't expose
    /proc/mounts and the deployment target is Linux/NAS anyway).
    """
    if os.name != "posix":
        return ""
    try:
        mounts = Path("/proc/mounts").read_text(encoding="utf-8")
    except OSError:
        return ""
    resolved = str(path.resolve())
    best_match = ""
    best_fs = ""
    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        mount_point, fs_type = parts[1], parts[2]
        if resolved.startswith(mount_point) and len(mount_point) > len(best_match):
            best_match = mount_point
            best_fs = fs_type
    return best_fs


def _chmod_db_file(path: Path) -> None:
    """Best-effort 0600 on the DB file (findings/scope/audit are sensitive).

    SQLite's -wal/-shm sidecar files inherit the directory umask, not this
    chmod; for full at-rest protection set ``umask 077`` in the systemd unit
    (see docs/deployment/linux.md). No-op on non-POSIX.
    """
    if os.name != "posix":
        return
    if path.exists():
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)


def create_sqlite_engine(path: Path) -> Engine:
    fs_type = _filesystem_type(path)
    if fs_type in _NETWORK_FS_TYPES and not os.environ.get("SECOPTENT_ALLOW_NFS_DB"):
        raise NetworkFilesystemError(
            f"SQLite database at {path} is on a network filesystem ('{fs_type}'); "
            "WAL file locks are unreliable there and the DB will silently corrupt. "
            "Use a local SSD path or set SECOPTENT_DB_URL to a PostgreSQL instance. "
            "To override at your own risk set SECOPTENT_ALLOW_NFS_DB=1."
        )
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False, "timeout": 5.0},
        future=True,
        # NullPool: each thread (request handler + background executor) gets
        # its own connection, avoiding StaticPool's single-shared-connection
        # contention. SQLite WAL handles the concurrency at the file level.
        poolclass=None,  # SQLAlchemy defaults to QueuePool for file-based SQLite
        pool_size=5,
        max_overflow=10,
    )

    @event.listens_for(engine, "connect")
    def configure(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        # §3.5 performance: synchronous=NORMAL is durable under WAL (only the
        # final commit fsync is skipped) and much faster than FULL; cap the WAL
        # file so a long-running assessment cannot grow it without bound.
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA journal_size_limit=67108864")
        cursor.close()

    _chmod_db_file(path)
    return engine
