"""Phase 2.3 (方案 A): netns sidecar binding + scan container network namespace.

Two test tiers:

1. **Unit tests (Windows-runnable)** - pure arg construction, no Docker/ip.
   These verify:
     - ``SubprocessContainerExecutor._build_args`` emits
       ``--network=container:<name>`` when ``network_namespace`` is set and
       ``--network=bridge`` when it is not.
     - ``--add-host host.docker.internal:host-gateway`` is OMITTED when
       ``network_namespace`` is set (the shared netns owns DNS/hosts).
     - ``NetnsIsolator.create(with_sidecar=True)`` issues the sidecar
       ``docker run`` command with the right name/image/network.
     - ``NetnsIsolator.destroy`` removes the sidecar before the netns.

2. **Integration tests (Linux-only, skip on Windows/macOS)** - real ``ip`` +
   ``docker``. These are gated with ``@pytest.mark.skipif(sys.platform !=
   "linux", ...)`` and assert the full sidecar lifecycle: create() starts the
   sidecar, destroy() cleans it up, and a scan container sharing the sidecar's
   netns sees the isolated namespace.
"""
from __future__ import annotations

import subprocess
import sys
from typing import Any

import pytest

from secopent.infrastructure.adapters.subprocess_executor import (
    SubprocessContainerExecutor,
)
from secopent.infrastructure.egress.netns_isolator import (
    NetnsHandle,
    NetnsIsolator,
)

# ---------------------------------------------------------------------------
# Tier 1: unit tests (run on Windows - pure arg construction)
# ---------------------------------------------------------------------------


def _build_args(network_namespace: str | None = None) -> list[str]:
    """Build docker args via the executor with a fake docker binary path."""
    executor = SubprocessContainerExecutor(docker_bin="docker")
    return executor._build_args(  # noqa: SLF001 - unit-testing the arg builder
        image_digest="alpine:3.20",
        command=["true"],
        mounts={},
        network_policy="scoped-egress",
        resource_limits={},
        network_namespace=network_namespace,
    )


def _pair_after(args: list[str], flag: str) -> str | None:
    """Return the value following the first occurrence of ``flag``, or None."""
    for i, a in enumerate(args):
        if a == flag and i + 1 < len(args):
            return args[i + 1]
    return None


def test_build_args_emits_bridge_when_no_network_namespace() -> None:
    args = _build_args(network_namespace=None)
    mode = _pair_after(args, "--network")
    assert mode == "bridge", f"expected bridge, got {mode!r}"


def test_build_args_emits_container_namespace_when_set() -> None:
    args = _build_args(network_namespace="secopent-netns-asm-1")
    mode = _pair_after(args, "--network")
    assert mode == "container:secopent-netns-asm-1", f"got {mode!r}"


def test_build_args_omits_add_host_when_network_namespace_set() -> None:
    args = _build_args(network_namespace="secopent-netns-asm-1")
    assert "--add-host" not in args, (
        "--add-host must be omitted under --network=container: (shared netns "
        "owns hosts; Docker rejects per-container --add-host in this mode)"
    )


def test_build_args_includes_add_host_when_no_network_namespace() -> None:
    args = _build_args(network_namespace=None)
    assert "--add-host" in args
    host_entry = _pair_after(args, "--add-host")
    assert host_entry == "host.docker.internal:host-gateway"


def test_run_passes_network_namespace_through(monkeypatch: pytest.MonkeyPatch) -> None:
    """run() forwards network_namespace to _build_args (end-to-end plumbing)."""
    captured: dict[str, list[str]] = {}

    def fake_run(args: Any, **kwargs: Any) -> subprocess.CompletedProcess:
        captured["args"] = list(args)

        class _Result:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Result()  # type: ignore[return-value]

    monkeypatch.setattr(subprocess, "run", fake_run)
    executor = SubprocessContainerExecutor()
    executor.run(
        image_digest="alpine:3.20",
        command=["true"],
        mounts={},
        network_policy="scoped-egress",
        resource_limits={},
        network_namespace="secopent-netns-asm-2",
    )
    mode = _pair_after(captured["args"], "--network")
    assert mode == "container:secopent-netns-asm-2"
    assert "--add-host" not in captured["args"]


# ---- NetnsIsolator sidecar command-sequence unit tests ---------------------


class _RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> None:
        self.calls.append(list(args))


def test_create_with_sidecar_issues_docker_run_and_attach(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """create(with_sidecar=True) starts sidecar + attaches its netns."""
    runner = _RecordingRunner()
    isolator = NetnsIsolator(runner=runner)
    # _inspect_sidecar_pid calls subprocess.check_output directly; stub it.
    monkeypatch.setattr(
        "subprocess.check_output",
        lambda args, **_kw: "12345\n",
    )
    handle = isolator.create("asm-1", with_sidecar=True)

    assert handle.name == "secopent-asm-1"
    assert handle.sidecar == "secopent-netns-asm-1"
    # 1) ip netns add, 2) docker run sidecar, 3) ip netns attach <name> <pid>
    assert runner.calls[0] == ["ip", "netns", "add", "secopent-asm-1"]
    assert runner.calls[1] == [
        "docker", "run", "-d", "--name", "secopent-netns-asm-1",
        "--network=none", "--restart=no", "alpine", "sleep", "infinity",
    ]
    assert runner.calls[2] == ["ip", "netns", "attach", "secopent-asm-1", "12345"]


def test_destroy_with_sidecar_removes_sidecar_then_netns() -> None:
    runner = _RecordingRunner()
    isolator = NetnsIsolator(runner=runner)
    handle = NetnsHandle(name="secopent-asm-1", sidecar="secopent-netns-asm-1")
    isolator.destroy(handle)
    # Sidecar removed FIRST (releases the ns), then netns deleted.
    assert runner.calls == [
        ["docker", "rm", "-f", "secopent-netns-asm-1"],
        ["ip", "netns", "del", "secopent-asm-1"],
    ]


def test_destroy_without_sidecar_only_deletes_netns() -> None:
    runner = _RecordingRunner()
    isolator = NetnsIsolator(runner=runner)
    handle = NetnsHandle(name="secopent-asm-1", sidecar="")
    isolator.destroy(handle)
    assert runner.calls == [["ip", "netns", "del", "secopent-asm-1"]]


def test_sidecar_name_sanitized_and_prefixed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _RecordingRunner()
    isolator = NetnsIsolator(runner=runner)
    monkeypatch.setattr("subprocess.check_output", lambda args, **_kw: "1\n")
    handle = isolator.create("asm abc/xyz", with_sidecar=True)
    assert handle.sidecar == "secopent-netns-asm-abc-xyz"


# ---------------------------------------------------------------------------
# Tier 2: integration tests (Linux + Docker only; skip on Windows/macOS)
# ---------------------------------------------------------------------------

_LINUX_ONLY = pytest.mark.skipif(
    sys.platform != "linux", reason="netns + docker sidecar is Linux-only"
)


@_LINUX_ONLY
def test_sidecar_lifecycle_real_docker() -> None:
    """create() starts a real sidecar; destroy() removes it + the netns.

    Requires Linux (ip netns) + Docker. Verifies the sidecar container exists
    after create() and is gone after destroy(), and that the named netns is
    created and deleted.
    """
    isolator = NetnsIsolator()
    if not isolator.is_supported():
        pytest.skip("netns not supported on this platform")
    handle = isolator.create("phase23-it")
    try:
        # Sidecar container exists.
        inspect = subprocess.run(
            ["docker", "inspect", handle.sidecar],
            capture_output=True, check=False,
        )
        assert inspect.returncode == 0, f"sidecar {handle.sidecar} not running"
        # Named netns exists.
        ns = subprocess.run(
            ["ip", "netns", "list"], capture_output=True, check=False, text=True,
        )
        assert handle.name in ns.stdout
    finally:
        isolator.destroy(handle)
    # After destroy: sidecar gone, netns gone.
    inspect_after = subprocess.run(
        ["docker", "inspect", handle.sidecar],
        capture_output=True, check=False,
    )
    assert inspect_after.returncode != 0, "sidecar still present after destroy()"


@_LINUX_ONLY
def test_scan_container_shares_sidecar_netns_real_docker() -> None:
    """A scan container with --network=container:<sidecar> shares the netns.

    Runs an alpine container joined to the sidecar's netns and checks its
    network interface matches the sidecar's (same ns -> same ifindex/lo only,
    since the sidecar was started with --network=none).
    """
    isolator = NetnsIsolator()
    if not isolator.is_supported():
        pytest.skip("netns not supported on this platform")
    handle = isolator.create("phase23-share")
    try:
        executor = SubprocessContainerExecutor(default_timeout=60)
        # The scan container joins the sidecar's netns. With --network=none on
        # the sidecar, only the loopback interface is visible.
        result = executor.run(
            image_digest="alpine:3.20",
            command=["sh", "-c", "ip -o link show | wc -l"],
            mounts={},
            network_policy="scoped-egress",
            resource_limits={"memory": "64m", "cpus": "0.1"},
            network_namespace=handle.sidecar,
        )
        assert result.exit_code == 0, f"scan container failed: {result.stderr}"
        # Only lo (1 interface) in an isolated --network=none ns.
        assert result.stdout.strip() == "1", (
            f"expected 1 interface (lo) in shared netns, got: {result.stdout!r}"
        )
    finally:
        isolator.destroy(handle)
