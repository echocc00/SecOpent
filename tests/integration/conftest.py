"""Integration test configuration: auto-skip when Docker is unavailable.

Integration tests (``@pytest.mark.integration``) require Docker + real tool
images + target ranges. In environments without Docker they are skipped so the
default ``pytest`` run stays fast and green; run them explicitly with
``pytest -m integration`` where Docker is available.
"""
from __future__ import annotations

import shutil

import pytest


def pytest_collection_modifyitems(config, items):  # type: ignore[no-untyped-def]
    if shutil.which("docker"):
        return
    skip_docker = pytest.mark.skip(reason="docker not available")
    for item in items:
        if "integration" in item.keywords or "e2e_real" in item.keywords:
            item.add_marker(skip_docker)
