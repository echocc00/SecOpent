# src/secopent/infrastructure/peer_agents/harness.py
"""ContainerPeerAgentHarness: run peer agents in hardened containers.

Reuses SubprocessContainerExecutor hardening (digest pinning, non-root,
cap-drop ALL, read-only rootfs, resource limits, bridge network). Each peer
run labels its container ``secopent.peer_run=<run_id>`` so:
- targeted stop can ``docker kill`` by label (this module's ``terminate``);
- the global Emergency Stop's DockerContainerTerminator (label
  ``secopent=execution``) still catches peer containers automatically.

Backends are per-agent strategies (P2: StrixBackend; P3: ShannonBackend).
P0 ships no real backend - contract tests use fakes.
"""
from __future__ import annotations

import subprocess
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from ...domain.common.errors import DomainError
from ...domain.peer_agents.models import (
    PeerAgentDescriptor,
    PeerAgentReport,
    PeerAgentRun,
)
from ..adapters.base import ContainerResult


class PeerAgentBackendMissing(DomainError):
    """No backend registered for this peer agent name."""


@dataclass(frozen=True, slots=True)
class PeerInvocation:
    """Everything the harness needs to run one peer agent container."""

    image_digest: str
    command: Sequence[str]
    mounts: Mapping[str, str]
    capabilities: Sequence[str]
    resource_limits: Mapping[str, object]


@runtime_checkable
class PeerAgentBackend(Protocol):
    """Per-agent invocation + report parsing strategy."""

    def build_invocation(
        self,
        run: PeerAgentRun,
        descriptor: PeerAgentDescriptor,
        workdir: Path,
    ) -> PeerInvocation: ...

    def parse_report(
        self, result: ContainerResult, workdir: Path
    ) -> PeerAgentReport: ...


class _Executor(Protocol):
    """Structural protocol for the container executor (matches
    SubprocessContainerExecutor.run including extra_labels)."""

    def run(
        self,
        *,
        image_digest: str,
        command: Sequence[str],
        mounts: Mapping[str, str],
        network_policy: str,
        resource_limits: Mapping[str, object],
        capabilities: Sequence[str] = (),
        extra_labels: Mapping[str, str] = ...,
    ) -> ContainerResult: ...


class ContainerPeerAgentHarness:
    """PeerAgentHarness backed by hardened docker containers."""

    def __init__(
        self,
        *,
        executor: _Executor,
        backends: Mapping[str, PeerAgentBackend],
        workdir_root: Path,
        docker_bin: str = "docker",
        terminate_timeout: int = 30,
    ) -> None:
        self._executor = executor
        self._backends = dict(backends)
        self._workdir_root = Path(workdir_root)
        self._docker = docker_bin
        self._terminate_timeout = terminate_timeout

    def execute(
        self, run: PeerAgentRun, descriptor: PeerAgentDescriptor
    ) -> PeerAgentReport:
        backend = self._backends.get(descriptor.name)
        if backend is None:
            raise PeerAgentBackendMissing(
                f"no peer agent backend registered: {descriptor.name}"
            )
        workdir = self._workdir_root / f"{run.id}-{uuid.uuid4().hex[:6]}"
        (workdir / "out").mkdir(parents=True, exist_ok=True)
        invocation = backend.build_invocation(run, descriptor, workdir)
        started = time.monotonic()
        result = self._executor.run(
            image_digest=invocation.image_digest,
            command=list(invocation.command),
            mounts=dict(invocation.mounts),
            network_policy="scoped-egress",
            resource_limits=dict(invocation.resource_limits),
            capabilities=tuple(invocation.capabilities),
            extra_labels={"secopent.peer_run": run.id},
        )
        wall = time.monotonic() - started
        report = backend.parse_report(result, workdir)
        # Backends report their own wall/cost; the harness guarantees wall is
        # at least the measured container wall (self-reported floor guard).
        return PeerAgentReport(
            run_id=run.id,
            findings=report.findings,
            wall_seconds=max(report.wall_seconds, wall),
            cost_units=report.cost_units,
            exit_code=report.exit_code,
        )

    def terminate(self, run_id: str) -> bool:
        """Kill containers labeled for this peer run; True if any were killed."""
        listed = subprocess.run(  # noqa: S603
            [
                self._docker,
                "ps",
                "-q",
                "--filter",
                f"label=secopent.peer_run={run_id}",
            ],
            capture_output=True,
            text=True,
            timeout=self._terminate_timeout,
            check=False,
        )
        container_ids = [c for c in listed.stdout.split() if c]
        if not container_ids:
            return False
        killed = subprocess.run(  # noqa: S603
            [self._docker, "kill", *container_ids],
            capture_output=True,
            text=True,
            timeout=self._terminate_timeout,
            check=False,
        )
        return killed.returncode == 0
