# tests/application/test_checkpoint_service.py
"""CheckpointService: phase snapshot + rollback on failure (P1b Task 2)."""
from __future__ import annotations

from pathlib import Path

import pytest

from secopent.application.checkpoint import (
    CheckpointService,
    PhaseFailedError,
)
from secopent.infrastructure.safety.workspace_snapshot import (
    WorkspaceSnapshotStore,
)


def _service(tmp_path: Path) -> CheckpointService:
    return CheckpointService(
        snapshots=WorkspaceSnapshotStore(root=tmp_path / "snaps"),
    )


class TestCheckpointPhase:
    def test_successful_phase_commits_and_returns_none(self, tmp_path) -> None:
        service = _service(tmp_path)
        workdir = tmp_path / "work"
        workdir.mkdir()
        (workdir / "f.txt").write_text("ok", encoding="utf-8")

        result = service.run_phase(
            job_id="job-1", phase="recon", workdir=workdir,
            action=lambda wdir: None,
        )
        assert result.rolled_back is False
        assert result.snapshot_id  # 快照已记录

    def test_failed_phase_rolls_back_workspace(self, tmp_path) -> None:
        service = _service(tmp_path)
        workdir = tmp_path / "work"
        workdir.mkdir()
        (workdir / "f.txt").write_text("before", encoding="utf-8")

        def break_phase(wdir: Path) -> None:
            (wdir / "f.txt").write_text("CORRUPTED", encoding="utf-8")
            raise ValueError("phase exploded")

        with pytest.raises(PhaseFailedError):
            service.run_phase(
                job_id="job-1", phase="exploit", workdir=workdir,
                action=break_phase,
            )
        assert (workdir / "f.txt").read_text(encoding="utf-8") == "before"

    def test_original_exception_is_chained(self, tmp_path) -> None:
        service = _service(tmp_path)
        workdir = tmp_path / "work"
        workdir.mkdir()

        def boom(wdir: Path) -> None:
            raise KeyError("root cause")

        with pytest.raises(PhaseFailedError) as excinfo:
            service.run_phase(
                job_id="job-1", phase="x", workdir=workdir, action=boom,
            )
        assert isinstance(excinfo.value.__cause__, KeyError)
