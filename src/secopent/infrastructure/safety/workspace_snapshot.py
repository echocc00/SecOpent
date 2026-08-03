# src/secopent/infrastructure/safety/workspace_snapshot.py
"""Workspace snapshots: phase-level tar archives for rollback (spec §7).

Inspired by Shannon's git checkpoint/rollback pattern, rewritten on plain
tar archives (no git dependency in the execution workspace, no AGPL code).
Snapshots exclude VCS metadata; restore wipes the target dir's contents
before extracting so removed files do not survive.
"""
from __future__ import annotations

import shutil
import tarfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from ...domain.common.errors import DomainError

_EXCLUDED_DIRS = {".git", ".hg", ".svn", "__pycache__", ".shannon"}


class SnapshotMissing(DomainError):
    """The snapshot id does not exist in the store."""


@dataclass(frozen=True, slots=True)
class SnapshotRef:
    id: str
    job_id: str
    phase: str
    path: Path


class WorkspaceSnapshotStore:
    """Tar-based snapshot store rooted at ``root`` (one .tar.gz per snapshot)."""

    def __init__(self, *, root: Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def create(self, job_id: str, phase: str, workdir: Path) -> str:
        snap_id = f"snap-{job_id}-{phase}-{uuid.uuid4().hex[:8]}"
        archive = self._root / f"{snap_id}.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for child in sorted(workdir.iterdir()):
                if child.name in _EXCLUDED_DIRS:
                    continue
                tar.add(child, arcname=child.name)
        return snap_id

    def restore(self, snap_id: str, workdir: Path) -> None:
        archive = self._root / f"{snap_id}.tar.gz"
        if not archive.exists():
            raise SnapshotMissing(f"snapshot not found: {snap_id}")
        workdir.mkdir(parents=True, exist_ok=True)
        for child in workdir.iterdir():
            _remove(child)
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(workdir, filter="data")  # noqa: S202 - filtered

    def list_for_job(self, job_id: str) -> tuple[SnapshotRef, ...]:
        refs: list[SnapshotRef] = []
        prefix = f"snap-{job_id}-"
        for archive in sorted(self._root.glob("snap-*.tar.gz")):
            stem = archive.stem
            if not stem.startswith(prefix):
                continue
            remainder = stem[len(prefix):]
            # remainder == "<phase>-<rand>" ; rand is 8 hex chars after last '-'
            last_dash = remainder.rfind("-")
            phase = remainder[:last_dash] if last_dash != -1 else remainder
            refs.append(SnapshotRef(
                id=stem, job_id=job_id, phase=phase, path=archive,
            ))
        return tuple(refs)


def _remove(child: Path) -> None:
    if child.is_dir():
        shutil.rmtree(child)
    else:
        child.unlink()
