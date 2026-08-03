"""Security test configuration: provides docker_mount_dir for bind-mount safety."""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest


def _is_bind_mount_safe(path: Path) -> bool:
    """Check whether a path is on a filesystem Docker can bind-mount reliably.

    Docker bind mounts from tmpfs-backed or overlay-backed directories may
    appear empty inside the container on certain kernel/filesystem combos
    (e.g. NAS appliances where /tmp is tmpfs with overlay subvolumes).
    """
    try:
        mounts_file = Path("/proc/mounts")
        if not mounts_file.exists():
            return True  # non-Linux - assume safe
        resolved = str(path.resolve())
        best_match = ""
        best_fs = ""
        for line in mounts_file.read_text().splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            mount_point, fs_type = parts[1], parts[2]
            if resolved.startswith(mount_point) and len(mount_point) > len(best_match):
                best_match = mount_point
                best_fs = fs_type
        return best_fs not in ("tmpfs", "overlay")
    except OSError:
        return True


@pytest.fixture
def docker_mount_dir(tmp_path: Path) -> Path:
    """Provide a directory safe for Docker bind mounts.

    On systems where pytest's tmp_path lands on tmpfs/overlay (NAS appliances,
    some CI containers), Docker bind mounts see an empty directory. This fixture
    detects that and relocates to a plain-filesystem path.
    """
    if _is_bind_mount_safe(tmp_path):
        return tmp_path

    fallback_base = Path("/var/tmp/secopent-test")
    if not _is_bind_mount_safe(fallback_base):
        fallback_base = Path(__file__).resolve().parents[2] / ".test-mounts"

    fallback_base.mkdir(parents=True, exist_ok=True)
    target = fallback_base / uuid.uuid4().hex[:12]
    target.mkdir(parents=True, exist_ok=True)
    return target
