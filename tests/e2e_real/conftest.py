"""e2e_real configuration: skip when Docker or the target ranges are unavailable.

These tests run REAL tool containers against REAL target ranges (Juice Shop on
:3000, httpbin on :8080). They are skipped when Docker is absent or a target is
down, so the default suite stays green anywhere; run them with
``pytest -m e2e_real`` on a provisioned machine (see scripts/verify_env.py).
"""
from __future__ import annotations

import shutil
import subprocess
import urllib.request
import uuid
from pathlib import Path

import pytest

_TARGETS = {
    "juice_shop": "http://localhost:3000",
    "httpbin": "http://localhost:8080",
}


def _docker_available() -> bool:
    """True only if the docker CLI exists AND the daemon responds.

    ``shutil.which`` alone is insufficient: Docker Desktop may be installed
    but stopped. ``docker info`` requires a live daemon, so tests SKIP (not
    fail) when the daemon is down.
    """
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=5, check=False,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _target_up(url: str) -> bool:
    # Force direct connection: urllib respects HTTP_PROXY by default, which
    # would route localhost traffic through a proxy that can't reach it,
    # causing false "target down" and silent test skipping.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=5) as resp:
            return resp.status == 200
    except Exception:  # noqa: BLE001 - any failure means the target is down
        return False


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
    detects that and relocates to a plain-filesystem path. Fallback directories
    are cleaned up after the test to avoid disk space leaks.
    """
    if _is_bind_mount_safe(tmp_path):
        yield tmp_path
        return

    fallback_base = Path("/var/tmp/secopent-test")
    if not _is_bind_mount_safe(fallback_base):
        fallback_base = Path(__file__).resolve().parents[2] / ".test-mounts"

    fallback_base.mkdir(parents=True, exist_ok=True)
    target = fallback_base / uuid.uuid4().hex[:12]
    target.mkdir(parents=True, exist_ok=True)
    yield target
    import shutil
    shutil.rmtree(target, ignore_errors=True)


def pytest_collection_modifyitems(config, items):  # type: ignore[no-untyped-def]
    if _docker_available():
        return
    skip = pytest.mark.skip(reason="docker not available")
    for item in items:
        if "e2e_real" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def require_target():  # type: ignore[no-untyped-def]
    """Return a checker that skips the test if the named target is down."""

    def _check(name: str) -> str:
        if not _docker_available():
            pytest.skip("docker not available")
        url = _TARGETS[name]
        if not _target_up(url):
            pytest.skip(f"target {name} ({url}) not reachable")
        return url

    return _check
