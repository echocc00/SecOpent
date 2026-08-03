# tests/infrastructure/test_subprocess_executor_labels.py
"""extra_labels support on SubprocessContainerExecutor (P0 Task 7).

Uses a fake docker binary (echoing args) so the test runs without Docker.
"""
from __future__ import annotations

import subprocess
from typing import Any

from secopent.infrastructure.adapters.subprocess_executor import (
    SubprocessContainerExecutor,
)


def test_extra_labels_appear_in_docker_args(monkeypatch: Any) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        captured.setdefault("args", list(args))

        class _Result:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Result()  # type: ignore[return-value]

    import subprocess as sp

    monkeypatch.setattr(sp, "run", fake_run)
    executor = SubprocessContainerExecutor(docker_bin="docker")
    executor.run(
        image_digest="alpine:3.20",  # tag-only: digest check skipped
        command=["true"],
        mounts={},
        network_policy="scoped-egress",
        resource_limits={},
        extra_labels={"secopent.peer_run": "peer-run-abc"},
    )
    args = captured["args"]
    # Both the existing secopent=execution label and the new peer label present
    labels = [args[i + 1] for i, a in enumerate(args) if a == "--label"]
    assert "secopent=execution" in labels
    assert "secopent.peer_run=peer-run-abc" in labels


def test_run_without_extra_labels_unchanged(monkeypatch: Any) -> None:
    def fake_run(args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        class _Result:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Result()  # type: ignore[return-value]

    import subprocess as sp

    monkeypatch.setattr(sp, "run", fake_run)
    executor = SubprocessContainerExecutor()
    result = executor.run(
        image_digest="alpine:3.20",
        command=["true"],
        mounts={},
        network_policy="scoped-egress",
        resource_limits={},
    )
    assert result.exit_code == 0
