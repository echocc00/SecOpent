"""NetnsIsolator command logic (W3-F T1) + Phase 2.3 sidecar binding (方案 A).

Unit tests for the command sequences issued by ``NetnsIsolator.create`` /
``destroy``. The runner is a recording fake so these run on any platform
(no real ``ip`` / ``docker`` binaries needed).

Phase 2.3 (方案 A): ``create(with_sidecar=True)`` additionally starts an
``alpine sleep infinity`` sidecar container and attaches its netns to the
named netns; ``destroy`` removes the sidecar before deleting the netns.

v0.5.1 F1/F3: ``is_supported()`` probes actual ``ip netns`` capability (not
just ``sys.platform``) and honors ``SECOPTENT_NETNS_ENABLED=0``; ``create()``
self-cleans a half-bound sidecar/netns pair when a later step fails.
"""
from __future__ import annotations

import subprocess
import sys

import pytest

from secopent.infrastructure.egress.netns_isolator import NetnsHandle, NetnsIsolator


class _RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> None:
        self.calls.append(list(args))


class _SelectiveFailingRunner:
    """Records calls and raises once a marker appears in the argv."""

    def __init__(self, fail_marker: str) -> None:
        self.calls: list[list[str]] = []
        self._fail_marker = fail_marker

    def __call__(self, args: list[str]) -> None:
        self.calls.append(list(args))
        if self._fail_marker in args:
            raise subprocess.CalledProcessError(1, args)


def _force_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")


def _stub_ip_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    """_inspect_sidecar_pid shells out to docker inspect -> stub the pid."""
    monkeypatch.setattr("subprocess.check_output", lambda *a, **k: "1234")


def test_create_issues_ip_netns_add_with_sanitized_name() -> None:
    runner = _RecordingRunner()
    isolator = NetnsIsolator(runner=runner)
    handle = isolator.create("asm-abc 123", with_sidecar=False)
    assert isinstance(handle, NetnsHandle)
    # Name sanitized (space -> -) + prefixed.
    assert handle.name == "secopent-asm-abc-123"
    assert handle.sidecar == ""
    assert runner.calls == [["ip", "netns", "add", "secopent-asm-abc-123"]]


def test_destroy_issues_ip_netns_del() -> None:
    runner = _RecordingRunner()
    isolator = NetnsIsolator(runner=runner)
    handle = isolator.create("asm-1", with_sidecar=False)
    runner.calls.clear()
    isolator.destroy(handle)
    assert runner.calls == [["ip", "netns", "del", "secopent-asm-1"]]


def test_is_supported_off_on_non_linux() -> None:
    """Non-Linux never probes - the platform gate is the fast path."""
    assert NetnsIsolator(runner=_RecordingRunner()).is_supported() is False


def test_is_supported_probes_capability_and_caches(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_linux(monkeypatch)
    calls: list[list[str]] = []

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        calls.append(list(args))
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    isolator = NetnsIsolator(runner=_RecordingRunner())
    assert isolator.is_supported() is True
    assert isolator.is_supported() is True  # cached: probe ran exactly once
    assert [c for c in calls if c[:3] == ["ip", "netns", "add"]] == [
        ["ip", "netns", "add", "secopent-probe"]
    ]
    assert [c for c in calls if c[:3] == ["ip", "netns", "del"]] == [
        ["ip", "netns", "del", "secopent-probe"]
    ]


def test_is_supported_false_when_probe_reports_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_linux(monkeypatch)

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(args, 1)  # ip netns add failed

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert NetnsIsolator(runner=_RecordingRunner()).is_supported() is False


def test_is_supported_false_when_ip_binary_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_linux(monkeypatch)

    def fake_run(*a: object, **k: object) -> None:
        raise FileNotFoundError("ip")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert NetnsIsolator(runner=_RecordingRunner()).is_supported() is False


def test_is_supported_disabled_by_env(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_linux(monkeypatch)
    monkeypatch.setenv("SECOPTENT_NETNS_ENABLED", "0")
    assert NetnsIsolator(runner=_RecordingRunner()).is_supported() is False


def test_create_with_sidecar_success_sequence(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_ip_pid(monkeypatch)
    runner = _RecordingRunner()
    isolator = NetnsIsolator(runner=runner)
    handle = isolator.create("asm-3")
    assert handle.sidecar == "secopent-netns-asm-3"
    assert runner.calls[0] == ["ip", "netns", "add", "secopent-asm-3"]
    assert runner.calls[1][0:2] == ["docker", "run"]
    assert runner.calls[-1] == ["ip", "netns", "attach", "secopent-asm-3", "1234"]


def test_create_self_cleans_when_attach_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """F3: a failed attach must not leave the sidecar/netns behind."""
    _stub_ip_pid(monkeypatch)
    runner = _SelectiveFailingRunner("attach")
    isolator = NetnsIsolator(runner=runner)
    with pytest.raises(subprocess.CalledProcessError):
        isolator.create("asm-1")
    assert ["docker", "rm", "-f", "secopent-netns-asm-1"] in runner.calls
    assert ["ip", "netns", "del", "secopent-asm-1"] in runner.calls
    # the netns file was created before the attach failed, then removed.
    add_idx = runner.calls.index(["ip", "netns", "add", "secopent-asm-1"])
    rm_idx = runner.calls.index(["docker", "rm", "-f", "secopent-netns-asm-1"])
    del_idx = runner.calls.index(["ip", "netns", "del", "secopent-asm-1"])
    assert add_idx < rm_idx < del_idx


def test_create_self_cleans_when_docker_run_fails() -> None:
    """F3: a failed sidecar start must also roll back the netns."""
    runner = _SelectiveFailingRunner("run")
    isolator = NetnsIsolator(runner=runner)
    with pytest.raises(subprocess.CalledProcessError):
        isolator.create("asm-2")
    assert ["docker", "rm", "-f", "secopent-netns-asm-2"] in runner.calls
    assert ["ip", "netns", "del", "secopent-asm-2"] in runner.calls


def test_custom_prefix() -> None:
    runner = _RecordingRunner()
    isolator = NetnsIsolator(runner=runner, prefix="scan-")
    handle = isolator.create("a1", with_sidecar=False)
    assert handle.name == "scan-a1"
    assert runner.calls[0] == ["ip", "netns", "add", "scan-a1"]
