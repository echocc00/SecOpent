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


def test_seccomp_is_never_disabled(monkeypatch: Any) -> None:
    """W2-B honesty: containers must never run seccomp=unconfined (Docker's
    default profile is always in effect)."""
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
    executor = SubprocessContainerExecutor()
    executor.run(
        image_digest="alpine:3.20",
        command=["true"],
        mounts={},
        network_policy="scoped-egress",
        resource_limits={},
    )
    args = captured["args"]
    security_opts = [
        args[i + 1] for i, a in enumerate(args) if a == "--security-opt"
    ]
    assert "seccomp=unconfined" not in security_opts


def test_env_flags_appear_alongside_home(monkeypatch: Any) -> None:
    """Regression: caller-supplied --env pairs coexist with HOME=/tmp (P2)."""
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
        image_digest="alpine:3.20",
        command=["true"],
        mounts={},
        network_policy="scoped-egress",
        resource_limits={},
        env={"STRIX_LLM": "openai/gpt-x", "LLM_API_KEY": "sk-test"},
    )
    args = captured["args"]
    env_pairs = [args[i + 1] for i, a in enumerate(args) if a == "--env"]
    assert "HOME=/tmp" in env_pairs
    assert "STRIX_LLM=openai/gpt-x" in env_pairs
    assert "LLM_API_KEY=sk-test" in env_pairs
