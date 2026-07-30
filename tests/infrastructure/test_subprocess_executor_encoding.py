# tests/infrastructure/test_subprocess_executor_encoding.py
"""Regression: SubprocessContainerExecutor must decode tool output as UTF-8.

On a non-UTF-8 locale (e.g. zh-CN Windows = gbk/cp936) decoding tool stdout with
the platform codec raises UnicodeDecodeError on output that carries non-ASCII
bytes (trivy JSON descriptions, internationalized nuclei matches), which silently
loses stdout and yields zero observations (surfaced by T5 §3.2 cloud scenario).
The executor must pin ``encoding="utf-8"`` (with ``errors="replace"``) so tool
output decodes regardless of the host locale - never ``text=True`` (locale codec).
"""
from __future__ import annotations

import subprocess
from typing import Any

from secopent.infrastructure.adapters import subprocess_executor as se_mod
from secopent.infrastructure.adapters.subprocess_executor import (
    SubprocessContainerExecutor,
)


class _RecordingRun:
    """Stands in for subprocess.run: records kwargs, returns an empty success."""

    def __init__(self) -> None:
        self.kwargs: list[dict[str, Any]] = []

    def __call__(self, *args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        self.kwargs.append(kwargs)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="{}", stderr="")


def test_executor_pins_utf8_decoding(monkeypatch: Any) -> None:
    recorded = _RecordingRun()
    monkeypatch.setattr(se_mod.subprocess, "run", recorded)
    executor = SubprocessContainerExecutor()
    # No "@" in the image ref -> _verify_digest is skipped, so exactly one
    # docker-run subprocess call is issued through the recorded stub.
    executor.run(
        image_digest="aquasec/trivy:latest",
        command=["image", "alpine"],
        mounts={},
        network_policy="bridge",
        resource_limits={},
    )
    assert recorded.kwargs, "executor issued no subprocess call"
    for kwargs in recorded.kwargs:
        assert kwargs.get("encoding") == "utf-8"
        assert kwargs.get("errors") == "replace"
        assert "text" not in kwargs  # never fall back to the locale codec


def test_build_args_maps_host_docker_internal_for_linux_ci() -> None:
    """Adapter containers must reach host-mapped targets via host.docker.internal.

    Docker Desktop defines it already; Linux runners/CI need the explicit
    ``host-gateway`` entry, so the executor always adds it (T7 - enables the
    e2e_real jobs on ubuntu CI without changing local behaviour).
    """
    executor = SubprocessContainerExecutor()
    args = executor._build_args("img", ["scan"], {}, "bridge", {})
    assert "--add-host" in args
    assert "host.docker.internal:host-gateway" in args
