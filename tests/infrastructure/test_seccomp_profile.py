# tests/infrastructure/test_seccomp_profile.py
"""Curated seccomp profile + executor wiring (M5 Phase 2.5).

Validates:
1. ``scripts/provision/secopent-seccomp.json`` is well-formed JSON with the
   required seccomp-profile structure (defaultAction, architectures, syscalls).
2. High-risk syscalls are DENIED (present in the SCMP_ACT_ERRNO deny group).
3. ``SubprocessContainerExecutor._build_args`` emits
   ``--security-opt seccomp=<path>`` when ``seccomp_profile`` is set, and emits
   NO ``--security-opt`` flag when it is ``None`` (Docker default, no regression).

These are pure JSON + arg-construction tests: they run on Windows (no Docker,
no strace). Per-adapter strace-based allowlist tightening is Linux-only and
DEFERRED.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from secopent.infrastructure.adapters.subprocess_executor import (
    SECCOPENT_SECCOMP_PROFILE,
    SubprocessContainerExecutor,
)

# Repo root = tests/ -> parent. The profile ships at
# scripts/provision/secopent-seccomp.json under the repo root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_PROFILE_PATH = _REPO_ROOT / SECCOPENT_SECCOMP_PROFILE

# High-risk syscalls that MUST be denied (M5 Phase 2.5 threat model). These are
# the kernel-escape / privilege-escalation / namespace-abuse surface; none are
# needed by SecOpent's adapters (network scanners, httpx, nuclei).
_DENIED_SYSCALLS = [
    "ptrace",       # inspect/modify other processes -> credential theft
    "bpf",          # load eBPF programs -> kernel read/write, container escape
    "keyctl",       # manipulate kernel keyring -> credential leak
    "mount",        # mount filesystems -> hostfs escape
    "umount2",      # unmount filesystems -> DoS / escape
    "reboot",       # reboot host -> DoS
    "kexec_load",   # load new kernel -> persistent rootkit
    "open_by_handle_at",  # open by inode handle -> hostfs escape
    "unshare",      # create new namespaces -> namespace-escape surface
    "setns",        # join existing namespace -> namespace-escape surface
    "clone3",       # CLONE_NEWUSER / CLONE_NEWNS -> namespace abuse
]


@pytest.fixture(scope="module")
def profile_json() -> dict[str, Any]:
    """Load and parse the curated seccomp profile once for the module."""
    assert _PROFILE_PATH.exists(), (
        f"seccomp profile not found at {_PROFILE_PATH}; the file must ship at "
        "scripts/provision/secopent-seccomp.json (M5 Phase 2.5)"
    )
    return json.loads(_PROFILE_PATH.read_text(encoding="utf-8"))


# --- Profile structure tests -------------------------------------------------

def test_profile_file_exists_at_documented_path() -> None:
    """The profile ships at the path exposed by SECCOPENT_SECCOMP_PROFILE."""
    assert _PROFILE_PATH.is_file(), (
        f"SECCOPENT_SECCOMP_PROFILE={SECCOPENT_SECCOMP_PROFILE} does not resolve "
        f"to a file under the repo root ({_PROFILE_PATH})"
    )


def test_profile_has_required_top_level_keys(profile_json: dict[str, Any]) -> None:
    """Docker requires defaultAction; architectures + syscalls are conventional."""
    assert profile_json["defaultAction"] == "SCMP_ACT_ALLOW", (
        "denylist strategy: defaultAction MUST be SCMP_ACT_ALLOW so unspecified "
        "syscalls behave exactly as Docker's default (no adapter regression)"
    )
    assert "architectures" in profile_json
    archs = profile_json["architectures"]
    assert "SCMP_ARCH_X86_64" in archs, "x86_64 is the primary host arch"
    assert "SCMP_ARCH_X86" in archs, "x86 (compat) is required for 32-bit tools"
    assert "syscalls" in profile_json
    assert isinstance(profile_json["syscalls"], list)
    assert profile_json["syscalls"], "syscalls list must not be empty"


def test_profile_has_a_deny_group_with_errno_action(
    profile_json: dict[str, Any],
) -> None:
    """At least one syscall group uses SCMP_ACT_ERRNO to deny high-risk syscalls."""
    deny_groups = [
        g for g in profile_json["syscalls"] if g.get("action") == "SCMP_ACT_ERRNO"
    ]
    assert deny_groups, (
        "no SCMP_ACT_ERRNO group found; the denylist strategy requires at least "
        "one group denying high-risk syscalls"
    )
    # Flatten all denied names across all deny groups.
    denied: set[str] = set()
    for group in deny_groups:
        denied.update(group["names"])
    # Sanity: the deny set is non-empty and not absurdly large (an allowlist of
    # ~300 would indicate the strategy was inverted).
    assert 10 < len(denied) < 100, (
        f"denied syscall count {len(denied)} is out of the expected range for a "
        "curated denylist (expected ~30-60 high-risk syscalls)"
    )


@pytest.mark.parametrize("syscall", _DENIED_SYSCALLS)
def test_high_risk_syscalls_are_denied(
    profile_json: dict[str, Any], syscall: str
) -> None:
    """Each high-risk syscall MUST appear in a SCMP_ACT_ERRNO deny group."""
    denied: set[str] = set()
    for group in profile_json["syscalls"]:
        if group.get("action") == "SCMP_ACT_ERRNO":
            denied.update(group["names"])
    assert syscall in denied, (
        f"{syscall!r} is NOT denied by the profile; it MUST be in a "
        "SCMP_ACT_ERRNO group (M5 Phase 2.5 high-risk syscall list)"
    )


def test_profile_does_not_allow_unconfined(profile_json: dict[str, Any]) -> None:
    """The profile must never relax to seccomp=unconfined semantics."""
    # defaultAction must be a real action, not a wildcard allow that defeats the
    # denylist. SCMP_ACT_ALLOW is the denylist default (permitted); the threat
    # would be a profile with no deny groups at all, which test_profile_has_a_
    # deny_group_with_errno_action already guards against.
    assert profile_json["defaultAction"] != "SCMP_ACT_LOG", (
        "SCMP_ACT_LOG only logs, never blocks - insufficient for high-risk syscalls"
    )


def test_profile_no_duplicate_syscalls_in_deny_groups(
    profile_json: dict[str, Any],
) -> None:
    """No syscall name may appear twice across deny groups (Docker rejects dupes)."""
    seen: set[str] = set()
    for group in profile_json["syscalls"]:
        if group.get("action") != "SCMP_ACT_ERRNO":
            continue
        for name in group["names"]:
            assert name not in seen, (
                f"duplicate syscall {name!r} across deny groups - Docker would "
                "reject the profile"
            )
            seen.add(name)


# --- Executor arg-construction tests -----------------------------------------

def _capture_args(monkeypatch: Any, **run_kwargs: Any) -> list[str]:
    """Run the executor with a fake docker binary and return captured argv."""
    captured: dict[str, list[str]] = {}

    def fake_run(args: Any, **_kwargs: Any) -> subprocess.CompletedProcess:
        captured.setdefault("args", list(args))

        class _Result:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Result()  # type: ignore[return-value]

    monkeypatch.setattr(subprocess, "run", fake_run)
    executor = SubprocessContainerExecutor(docker_bin="docker")
    executor.run(
        image_digest="alpine:3.20",  # tag-only: digest check skipped
        command=["true"],
        mounts={},
        network_policy="scoped-egress",
        resource_limits={},
        **run_kwargs,
    )
    return captured["args"]


def test_seccomp_profile_emits_security_opt(monkeypatch: Any) -> None:
    """With seccomp_profile set, _build_args emits --security-opt seccomp=<path>."""
    args = _capture_args(
        monkeypatch, seccomp_profile="scripts/provision/secopent-seccomp.json"
    )
    security_opts = [
        args[i + 1] for i, a in enumerate(args) if a == "--security-opt"
    ]
    assert security_opts, "no --security-opt flag emitted when seccomp_profile is set"
    assert any(
        opt.startswith("seccomp=scripts/provision/secopent-seccomp.json")
        for opt in security_opts
    ), f"seccomp profile path not in security_opts: {security_opts}"


def test_no_seccomp_flag_when_profile_is_none(monkeypatch: Any) -> None:
    """Without seccomp_profile, NO --security-opt flag is emitted (Docker default)."""
    args = _capture_args(monkeypatch)  # seccomp_profile defaults to None
    security_opts = [
        args[i + 1] for i, a in enumerate(args) if a == "--security-opt"
    ]
    assert security_opts == [], (
        f"--security-opt emitted without seccomp_profile (would regress the "
        f"Docker-default behavior): {security_opts}"
    )


def test_seccomp_flag_is_never_unconfined(monkeypatch: Any) -> None:
    """seccomp=unconfined must NEVER appear, even when a profile path is set."""
    args = _capture_args(
        monkeypatch, seccomp_profile="scripts/provision/secopent-seccomp.json"
    )
    security_opts = [
        args[i + 1] for i, a in enumerate(args) if a == "--security-opt"
    ]
    assert "seccomp=unconfined" not in security_opts, (
        "seccomp=unconfined disables Docker's default protections - forbidden"
    )


def test_seccomp_profile_constant_is_relative_path() -> None:
    """SECCOPENT_SECCOMP_PROFILE is a repo-relative path (not absolute, not None)."""
    assert isinstance(SECCOPENT_SECCOMP_PROFILE, Path)
    assert not SECCOPENT_SECCOMP_PROFILE.is_absolute(), (
        "SECCOPENT_SECCOMP_PROFILE must be repo-relative so it resolves on any "
        "checkout; absolute paths break portability"
    )
    assert SECCOPENT_SECCOMP_PROFILE.as_posix() == "scripts/provision/secopent-seccomp.json"
