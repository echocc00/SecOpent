# tests/infrastructure/test_peer_agent_harness.py
"""ContainerPeerAgentHarness tests with fake executor + fake backend."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from secopent.domain.peer_agents.models import (
    PeerAgentBudget,
    PeerAgentDescriptor,
    PeerAgentReport,
    PeerAgentRun,
    PeerAgentTrustLevel,
)
from secopent.infrastructure.adapters.base import ContainerResult
from secopent.infrastructure.peer_agents.harness import (
    ContainerPeerAgentHarness,
    PeerAgentBackendMissing,
    PeerInvocation,
)


def _descriptor() -> PeerAgentDescriptor:
    return PeerAgentDescriptor(
        name="fakepeer",
        version="1.0",
        license="MIT",
        trust_level=PeerAgentTrustLevel.ADOPTED_EXTERNAL,
        capabilities=("web",),
        cost_class="llm_tokens",
        default_budget=PeerAgentBudget(max_wall_seconds=60, max_cost_units=5),
        image_digest="fake/peer@sha256:" + "a" * 64,
    )


def _run() -> PeerAgentRun:
    return PeerAgentRun(
        id="peer-run-1",
        agent_name="fakepeer",
        agent_version="1.0",
        assessment_id="asmt-1",
        targets=("http://host.docker.internal:3000",),
        budget=PeerAgentBudget(max_wall_seconds=60, max_cost_units=5),
        permit_id="p-1",
    )


class FakeBackend:
    def build_invocation(
        self, run: PeerAgentRun, descriptor: PeerAgentDescriptor, workdir: Path
    ) -> PeerInvocation:
        return PeerInvocation(
            image_digest=descriptor.image_digest,
            command=("fakepeer", "--target", run.targets[0]),
            mounts={"/work/output": str(workdir / "out")},
            capabilities=(),
            resource_limits={"memory_mb": 1024, "cpus": "1"},
        )

    def parse_report(
        self, result: ContainerResult, workdir: Path
    ) -> PeerAgentReport:
        return PeerAgentReport(
            run_id="peer-run-1",
            findings=(),
            wall_seconds=1.0,
            cost_units=0.5,
            exit_code=result.exit_code,
        )


class FakeExecutor:
    def __init__(self, result: ContainerResult | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.result = result or ContainerResult(
            stdout="", stderr="", exit_code=0, artifacts_dir=Path(".")
        )

    def run(self, **kwargs: Any) -> ContainerResult:
        self.calls.append(kwargs)
        return self.result


class TestHarnessExecute:
    def test_execute_invokes_executor_with_hardening(self, tmp_path: Path) -> None:
        executor = FakeExecutor()
        harness = ContainerPeerAgentHarness(
            executor=executor,
            backends={"fakepeer": FakeBackend()},
            workdir_root=tmp_path,
        )
        report = harness.execute(_run(), _descriptor())
        assert report.exit_code == 0
        call = executor.calls[0]
        assert call["image_digest"].startswith("fake/peer@sha256:")
        assert call["network_policy"] == "scoped-egress"
        assert call["extra_labels"] == {"secopent.peer_run": "peer-run-1"}

    def test_missing_backend_raises(self, tmp_path: Path) -> None:
        harness = ContainerPeerAgentHarness(
            executor=FakeExecutor(),
            backends={},
            workdir_root=tmp_path,
        )
        with pytest.raises(PeerAgentBackendMissing):
            harness.execute(_run(), _descriptor())


class TestHarnessTerminate:
    def test_terminate_kills_labeled_containers(
        self, monkeypatch: Any
    ) -> None:
        calls: list[list[str]] = []

        def fake_run(args: Any, **kwargs: Any) -> Any:
            calls.append(list(args))

            class _Result:
                returncode = 0
                stdout = "cid1\n" if args[1] == "ps" else ""
                stderr = ""

            return _Result()

        monkeypatch.setattr(subprocess, "run", fake_run)
        harness = ContainerPeerAgentHarness(
            executor=FakeExecutor(),
            backends={},
            workdir_root=Path("."),
            docker_bin="docker",
        )
        assert harness.terminate("peer-run-1") is True
        assert any(c[:2] == ["docker", "ps"] for c in calls)
        assert any(c[:2] == ["docker", "kill"] and "cid1" in c for c in calls)

    def test_terminate_no_containers_returns_false(
        self, monkeypatch: Any
    ) -> None:
        def fake_run(args: Any, **kwargs: Any) -> Any:
            class _Result:
                returncode = 0
                stdout = ""
                stderr = ""

            return _Result()

        monkeypatch.setattr(subprocess, "run", fake_run)
        harness = ContainerPeerAgentHarness(
            executor=FakeExecutor(),
            backends={},
            workdir_root=Path("."),
        )
        assert harness.terminate("peer-run-x") is False
