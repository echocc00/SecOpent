# src/secopent/infrastructure/adapters/subprocess_executor.py
"""SubprocessContainerExecutor: real `docker run` execution (Phase A Task A2).

The production ``ContainerExecutor`` (the Protocol is defined in ``base.py``).
It runs a digest-pinned tool image under the §8.4 hardening flags and captures
stdout/stderr/exit-code/artifacts.

Security guarantees enforced here:
- **digest pinning**: the image is only run if the exact pinned digest is present
  locally (``docker image inspect <name@digest>``); a mismatch raises
  ``ImageDigestMismatch`` (supply-chain defense);
- **non-root**: ``--user 65532:65532``;
- **no capabilities**: ``--cap-drop ALL``;
- **read-only rootfs**: ``--read-only`` with a ``noexec,nosuid`` tmpfs at /tmp;
- **resource limits**: ``--memory`` / ``--cpus``;
- **network**: option c bridge (see ``egress/network_policy.py``) - scope is
  enforced at the application layer (PolicyEngine); M5 strengthens this to
  nftables/netns network isolation.

A timeout returns ``exit_code=124`` (matching the timeout(1) convention) rather
than raising, so the AdapterRunner records it as a non-completed run.
"""
from __future__ import annotations

import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ...domain.common.errors import DomainError
from .base import ContainerResult

# Conventional mount destinations (the AdapterRunner uses /in and /out; the A2
# integration tests and real tools use /work/input and /work/output).
_OUTPUT_KEYS = ("/work/output", "/out")


class ImageDigestMismatch(DomainError):
    """The image is not present at the pinned digest (supply-chain guard)."""


class MountNotVisibleError(DomainError):
    """A bind-mounted host directory is empty inside the container.

    Raised when the host filesystem backing a mount source is not visible to
    Docker bind mounts (e.g. tmpfs + overlay on some NAS kernels). The caller
    should relocate the source directory to a plain filesystem (ext4/btrfs/xfs)
    and retry.
    """


class SubprocessContainerExecutor:
    """Run digest-pinned tool containers via ``docker run``.

    Satisfies the ``ContainerExecutor`` Protocol structurally. ``docker_bin``
    and timeouts are injectable for testing.
    """

    def __init__(
        self,
        docker_bin: str = "docker",
        default_timeout: int = 600,
        inspect_timeout: int = 30,
        max_workers: int = 1,
    ) -> None:
        if max_workers < 1:
            raise ValueError(f"max_workers must be >= 1, got {max_workers}")
        self._docker = docker_bin
        self._timeout = default_timeout
        self._inspect_timeout = inspect_timeout
        self._max_workers = max_workers

    def run_many(
        self, invocations: Sequence[Mapping[str, Any]]
    ) -> list[ContainerResult]:
        """Run multiple container invocations, concurrently when max_workers>1.

        Each invocation is the kwargs for one ``run`` call. With a single worker
        (default) this is a plain serial map; with ``max_workers > 1`` the runs
        overlap on a thread pool (P3 §3.5 / T4). Results preserve input order.
        """
        if self._max_workers <= 1 or len(invocations) <= 1:
            return [self.run(**invocation) for invocation in invocations]
        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            return list(pool.map(lambda invocation: self.run(**invocation), invocations))

    def run(
        self,
        *,
        image_digest: str,
        command: Sequence[str],
        mounts: Mapping[str, str],
        network_policy: str,
        resource_limits: Mapping[str, Any],
        capabilities: Sequence[str] = (),
    ) -> ContainerResult:
        """Verify the digest, run the container, and capture its output.

        ``capabilities``: Linux capabilities to ADD back after ``--cap-drop ALL``
        (e.g. ``("NET_RAW",)`` for nmap/naabu SYN scanning). Empty by default.
        """
        self._verify_digest(image_digest)
        args = self._build_args(
            image_digest, command, mounts, network_policy, resource_limits,
            capabilities,
        )
        artifacts_dir = self._artifacts_dir(mounts)
        try:
            proc = subprocess.run(  # noqa: S603 - args are constructed, not shell
                args,
                capture_output=True,
                # Tool output is UTF-8; never let the platform locale (e.g.
                # gbk/cp936 on zh-CN Windows) fail the decode and lose stdout
                # (T5 §3.2 - trivy JSON carries non-ASCII descriptions).
                encoding="utf-8",
                errors="replace",
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ContainerResult(
                stdout="",
                stderr=f"execution timeout after {self._timeout}s",
                exit_code=124,
                artifacts_dir=artifacts_dir,
            )
        return ContainerResult(
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            artifacts_dir=artifacts_dir,
        )

    def _verify_digest(self, image_digest: str) -> None:
        """Ensure the image is present at the pinned digest (reject mismatch).

        A tag-only reference (no ``@digest``) has nothing to pin and is allowed.
        A digest-pinned reference must resolve locally to that exact digest.
        """
        if "@" not in image_digest:
            return
        result = subprocess.run(  # noqa: S603
            [self._docker, "image", "inspect", image_digest],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=self._inspect_timeout,
            check=False,
        )
        if result.returncode != 0:
            raise ImageDigestMismatch(
                f"image not present at pinned digest: {image_digest}"
            )

    def _build_args(
        self,
        image_digest: str,
        command: Sequence[str],
        mounts: Mapping[str, str],
        network_policy: str,
        resource_limits: Mapping[str, Any],
        capabilities: Sequence[str] = (),
    ) -> list[str]:
        args = [
            self._docker,
            "run",
            "--rm",
            # Label every execution container so the emergency stop
            # (DockerContainerTerminator) can find and kill them (§12).
            "--label",
            "secopent=execution",
            # Let the tool container reach host-mapped targets (Juice Shop,
            # httpbin, ...) via host.docker.internal. Docker Desktop defines it
            # already (harmless re-map); Linux runners/CI need the explicit
            # host-gateway entry (T7 - enables e2e_real on ubuntu CI).
            "--add-host",
            "host.docker.internal:host-gateway",
            "--user",
            "65532:65532",
            "--cap-drop",
            "ALL",
        ]
        # Re-add specific capabilities needed by certain tools (e.g. NET_RAW
        # for nmap/naabu SYN scanning). Principle of least privilege: only the
        # explicitly requested caps are restored, never a broad set.
        for cap in capabilities:
            args += ["--cap-add", cap]
        args += [
            "--read-only",
            "--tmpfs",
            # nosec B108 - "/tmp" here is a container-internal tmpfs mount
            # (hardened: rw,noexec,nosuid), not predictable host temp usage.
            "/tmp:rw,noexec,nosuid,size=256m",
            # Non-root tools need a writable HOME under the read-only rootfs
            # (e.g. nuclei writes its config to $HOME/.config). The /tmp tmpfs
            # is writable, so point HOME there.
            "--env",
            "HOME=/tmp",
            "--network",
            self._network_mode(network_policy),
            "--memory",
            self._memory(resource_limits),
            "--cpus",
            self._cpus(resource_limits),
            # Fuzzers (schemathesis/restler) open many concurrent connections;
            # the container default nofile=1024 EMFILEs them. 65536 is safe for
            # all adapters (<= fs.nr_open, default 1048576 on Linux).
            "--ulimit",
            "nofile=65536:65536",
            "--workdir",
            "/work",
        ]
        for destination, source in mounts.items():
            args += ["-v", f"{source}:{destination}"]
        args.append(image_digest)
        args += list(command)
        return args

    @staticmethod
    def _network_mode(network_policy: str) -> str:
        # option c: bridge network + application-layer scope enforcement.
        # M5 strengthens to nftables/netns network isolation.
        return "bridge"

    @staticmethod
    def _memory(resource_limits: Mapping[str, Any]) -> str:
        if "memory" in resource_limits:
            return str(resource_limits["memory"])
        return f"{resource_limits.get('memory_mb', 512)}m"

    @staticmethod
    def _cpus(resource_limits: Mapping[str, Any]) -> str:
        return str(resource_limits.get("cpus", resource_limits.get("cpu_quota", "0.5")))

    @staticmethod
    def _artifacts_dir(mounts: Mapping[str, str]) -> Path:
        for key in _OUTPUT_KEYS:
            if key in mounts:
                return Path(mounts[key])
        return Path(tempfile.gettempdir())
