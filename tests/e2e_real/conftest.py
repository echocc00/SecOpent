"""e2e_real configuration: skip when Docker or the target ranges are unavailable.

These tests run REAL tool containers against REAL target ranges (Juice Shop on
:3000, httpbin on :8080). They are skipped when Docker is absent or a target is
down, so the default suite stays green anywhere; run them with
``pytest -m e2e_real`` on a provisioned machine (see scripts/verify_env.py).
"""
from __future__ import annotations

import shutil
import urllib.request

import pytest

_TARGETS = {
    "juice_shop": "http://localhost:3000",
    "httpbin": "http://localhost:8080",
}


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _target_up(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status == 200
    except Exception:  # noqa: BLE001 - any failure means the target is down
        return False


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
