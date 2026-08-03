# tests/infrastructure/test_workspace_snapshot.py
"""Workspace snapshot IO (P1b Task 1) - tar-based, deterministic."""
from __future__ import annotations

from pathlib import Path

from secopent.infrastructure.safety.workspace_snapshot import (
    SnapshotMissing,
    WorkspaceSnapshotStore,
)


class TestSnapshotRoundtrip:
    def test_create_and_restore_restores_file_contents(self, tmp_path: Path) -> None:
        workdir = tmp_path / "work"
        (workdir / "sub").mkdir(parents=True)
        (workdir / "a.txt").write_text("v1", encoding="utf-8")
        (workdir / "sub" / "b.txt").write_text("v2", encoding="utf-8")
        store = WorkspaceSnapshotStore(root=tmp_path / "snapshots")

        snap_id = store.create("job-1", "phase-recon", workdir)

        # 修改工作区后恢复，应回到快照状态
        (workdir / "a.txt").write_text("TAMPERED", encoding="utf-8")
        (workdir / "sub" / "b.txt").unlink()
        store.restore(snap_id, workdir)
        assert (workdir / "a.txt").read_text(encoding="utf-8") == "v1"
        assert (workdir / "sub" / "b.txt").read_text(encoding="utf-8") == "v2"

    def test_restore_unknown_snapshot_raises(self, tmp_path: Path) -> None:
        import pytest

        store = WorkspaceSnapshotStore(root=tmp_path / "snapshots")
        with pytest.raises(SnapshotMissing):
            store.restore("nope", tmp_path)

    def test_list_returns_snapshots_for_job(self, tmp_path: Path) -> None:
        workdir = tmp_path / "work"
        workdir.mkdir()
        (workdir / "f.txt").write_text("x", encoding="utf-8")
        store = WorkspaceSnapshotStore(root=tmp_path / "snapshots")
        store.create("job-1", "phase-a", workdir)
        store.create("job-1", "phase-b", workdir)
        store.create("job-2", "phase-a", workdir)
        phases = [s.phase for s in store.list_for_job("job-1")]
        assert phases == ["phase-a", "phase-b"]

    def test_create_excludes_snapshot_dir_and_vcs(self, tmp_path: Path) -> None:
        workdir = tmp_path / "work"
        (workdir / ".git").mkdir(parents=True)
        (workdir / ".git" / "HEAD").write_text("ref", encoding="utf-8")
        (workdir / "keep.txt").write_text("k", encoding="utf-8")
        store = WorkspaceSnapshotStore(root=tmp_path / "snapshots")
        snap_id = store.create("job-1", "phase-a", workdir)
        # 恢复到新目录验证 .git 未被打包
        target = tmp_path / "restored"
        target.mkdir()
        store.restore(snap_id, target)
        assert not (target / ".git").exists()
        assert (target / "keep.txt").exists()
