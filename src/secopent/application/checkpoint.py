# src/secopent/application/checkpoint.py
"""CheckpointService: phase-level snapshot/rollback for job execution (§7).

Wraps one phase of job execution: snapshot BEFORE, run the action, and on
any exception restore the snapshot and re-raise as PhaseFailedError (with
the original chained). Successful phases keep their snapshot as the next
phase's rollback point (list retained; pruning is ops policy).

Deterministic layer - no LLM involvement (LLM边界).
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..domain.common.errors import DomainError
from ..infrastructure.safety.workspace_snapshot import WorkspaceSnapshotStore


class PhaseFailedError(DomainError):
    """A phase raised; the workspace was rolled back to the phase start."""


@dataclass(frozen=True, slots=True)
class PhaseResult:
    snapshot_id: str
    rolled_back: bool


class CheckpointService:
    """Snapshot-run-rollback wrapper around phase actions."""

    def __init__(self, *, snapshots: WorkspaceSnapshotStore) -> None:
        self._snapshots = snapshots

    def run_phase(
        self,
        *,
        job_id: str,
        phase: str,
        workdir: Path,
        action: Callable[[Path], None],
    ) -> PhaseResult:
        snapshot_id = self._snapshots.create(job_id, phase, workdir)
        try:
            action(workdir)
        except Exception as exc:
            self._snapshots.restore(snapshot_id, workdir)
            raise PhaseFailedError(
                f"phase '{phase}' of job '{job_id}' failed; workspace "
                f"rolled back to snapshot {snapshot_id}"
            ) from exc
        return PhaseResult(snapshot_id=snapshot_id, rolled_back=False)
