"""Environment gates for Docker integration tests (shared helpers).

Kept in a plain module (NOT conftest.py) so tests can import it unambiguously:
pytest loads multiple ``conftest`` modules per session (one per directory), and
``from conftest import ...`` resolves to whichever one pytest registered first
- which breaks when several test dirs run in one session.
"""
from __future__ import annotations

import socket
import subprocess

import pytest


def _pinned_image_present(ref: str) -> bool:
    """True if the image exists locally at the exact pinned digest."""
    try:
        return subprocess.run(
            ["docker", "image", "inspect", ref],
            capture_output=True,
            timeout=15,
            check=False,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def skip_if_digest_drifted(*catalog_keys: str) -> None:
    """Skip (not fail) when a catalog-pinned image is absent from the local cache.

    The executor rejecting a drifted image is the supply-chain guard working as
    designed; a red suite would conflate "guard works" with "regression". CI
    pulls exact digests so these tests run there; a dev host whose image cache
    drifted (or was pruned) gets an actionable skip instead.
    """
    from secopent.infrastructure.adapters.image_catalog import IMAGE_CATALOG

    for key in catalog_keys:
        entry = IMAGE_CATALOG[key]
        if not entry.digest:
            continue  # unpinned entry - nothing to verify locally
        ref = f"{entry.name}@{entry.digest}"
        if not _pinned_image_present(ref):
            pytest.skip(
                f"{key} not present at pinned digest; re-pull with: docker pull {ref}"
            )


def skip_if_target_down(host: str, port: int) -> None:
    """Skip when an externally provisioned target range is not running.

    Integration tests that need a live target (e.g. httpbin on :8080, started
    by CI service containers or scripts/provision locally) must skip - not
    fail - when the range is simply not up on this host.
    """
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return
    except OSError:
        pytest.skip(f"target range not running: {host}:{port}")
