"""Integration test configuration: auto-skip when Docker is unavailable.

Integration tests (``@pytest.mark.integration``) require Docker + real tool
images + target ranges. In environments without Docker they are skipped so the
default ``pytest`` run stays fast and green; run them explicitly with
``pytest -m integration`` where Docker is available.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def _docker_daemon_reachable() -> bool:
    """True only if the docker CLI exists AND the daemon responds.

    ``shutil.which`` alone is insufficient: Docker Desktop may be installed
    but stopped, in which case integration tests must SKIP (not fail at the
    first ``docker image inspect``). ``docker info`` requires a live daemon.
    """
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=5, check=False,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def pytest_collection_modifyitems(config, items):  # type: ignore[no-untyped-def]
    if _docker_daemon_reachable():
        return
    skip_docker = pytest.mark.skip(reason="docker daemon not reachable")
    for item in items:
        if "integration" in item.keywords or "e2e_real" in item.keywords:
            item.add_marker(skip_docker)


def _is_bind_mount_safe(path: Path) -> bool:
    """Check whether a path is on a filesystem Docker can bind-mount reliably.

    Docker bind mounts from tmpfs-backed or overlay-backed directories may
    appear empty inside the container on certain kernel/filesystem combos
    (e.g. NAS appliances where /tmp is tmpfs with overlay subvolumes).
    A path is considered safe if its most-specific mount is NOT tmpfs/overlay.
    """
    try:
        # Linux: check the filesystem type via /proc/mounts
        mounts_file = Path("/proc/mounts")
        if not mounts_file.exists():
            return True  # non-Linux (Windows/macOS Docker Desktop) - assume safe
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
        return True  # cannot determine - assume safe


@pytest.fixture
def docker_mount_dir(tmp_path: Path) -> Path:
    """Provide a directory safe for Docker bind mounts.

    On systems where pytest's tmp_path lands on tmpfs/overlay (NAS appliances,
    some CI containers), Docker bind mounts see an empty directory. This fixture
    detects that and relocates to a plain-filesystem path under /var/tmp or
    the project's own directory. Fallback directories are cleaned up after the
    test to avoid disk space leaks on repeated runs.

    Usage in tests::

        def test_something(docker_mount_dir: Path) -> None:
            (docker_mount_dir / "templates").mkdir()
            ...
            mounts = {"/templates": str(docker_mount_dir / "templates")}
    """
    if _is_bind_mount_safe(tmp_path):
        yield tmp_path
        return

    # Fallback: /var/tmp is almost always on the root filesystem (ext4/btrfs/xfs)
    fallback_base = Path("/var/tmp/secopent-test")
    if not _is_bind_mount_safe(fallback_base):
        # Last resort: use the project directory itself
        fallback_base = Path(__file__).resolve().parents[2] / ".test-mounts"

    fallback_base.mkdir(parents=True, exist_ok=True)
    # Create a unique subdirectory per test (mirrors tmp_path semantics)
    import shutil
    import uuid

    target = fallback_base / uuid.uuid4().hex[:12]
    target.mkdir(parents=True, exist_ok=True)
    yield target
    # Cleanup after test to prevent disk space accumulation
    shutil.rmtree(target, ignore_errors=True)
