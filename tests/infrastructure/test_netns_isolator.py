"""NetnsIsolator command logic (W3-F T1)."""
from __future__ import annotations

from secopent.infrastructure.egress.netns_isolator import NetnsHandle, NetnsIsolator


class _RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> None:
        self.calls.append(list(args))


def test_create_issues_ip_netns_add_with_sanitized_name() -> None:
    runner = _RecordingRunner()
    isolator = NetnsIsolator(runner=runner)
    handle = isolator.create("asm-abc 123")
    assert isinstance(handle, NetnsHandle)
    # Name sanitized (space -> -) + prefixed.
    assert handle.name == "secopent-asm-abc-123"
    assert runner.calls == [["ip", "netns", "add", "secopent-asm-abc-123"]]


def test_destroy_issues_ip_netns_del() -> None:
    runner = _RecordingRunner()
    isolator = NetnsIsolator(runner=runner)
    handle = isolator.create("asm-1")
    runner.calls.clear()
    isolator.destroy(handle)
    assert runner.calls == [["ip", "netns", "del", "secopent-asm-1"]]


def test_is_supported_only_on_linux() -> None:
    isolator = NetnsIsolator(runner=_RecordingRunner())
    # On the test host (Windows/non-Linux) this is False; on Linux CI True.
    assert isolator.is_supported() == (__import__("sys").platform == "linux")


def test_custom_prefix() -> None:
    runner = _RecordingRunner()
    isolator = NetnsIsolator(runner=runner, prefix="scan-")
    handle = isolator.create("a1")
    assert handle.name == "scan-a1"
    assert runner.calls[0] == ["ip", "netns", "add", "scan-a1"]
