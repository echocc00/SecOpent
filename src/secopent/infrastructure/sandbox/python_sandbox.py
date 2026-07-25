# src/secopent/infrastructure/sandbox/python_sandbox.py
"""PythonPluginSandbox: isolated execution of Python case plugins (§11.4).

A plugin is statically scanned before it runs: forbidden module imports
(subprocess/os/socket/docker/ctypes/importlib/shutil) and forbidden calls
(eval/exec/compile/__import__/open/getattr) are rejected - the plugin can only
reach the world through the CaseContext SDK. The actual isolation (seccomp
profile + read-only/non-root/cap-drop ALL/no-new-privileges/no-host-network/
no-docker-socket container) is provided by an injected ``SandboxRuntime``
(Docker in M5; a mock in tests). seccomp is the M2-locked isolation choice: it
is lighter than gVisor and runs on the 2C2G Lite target.
"""
from __future__ import annotations

import ast
from typing import Any, Protocol, runtime_checkable

from secopent.domain.common.errors import DomainError

from .case_context import CaseContext

# Modules a plugin must never import (host/process/network escape vectors).
FORBIDDEN_MODULES: frozenset[str] = frozenset(
    {"subprocess", "os", "socket", "shutil", "docker", "ctypes", "importlib", "sys"}
)

# Bare calls a plugin must never make.
FORBIDDEN_CALLS: frozenset[str] = frozenset(
    {"eval", "exec", "compile", "__import__", "open", "getattr", "globals", "breakpoint"}
)

# §11.4 container hardening flags handed to the runtime.
SANDBOX_SECURITY_FLAGS: dict[str, Any] = {
    "read_only": True,
    "non_root": True,
    "cap_drop_all": True,
    "no_new_privileges": True,
    "host_network": False,
    "docker_socket": False,
}

# Default resource envelope (tuned for the 2C2G Lite target).
DEFAULT_RESOURCE_LIMITS: dict[str, Any] = {
    "cpu_quota": "0.5",
    "memory_mb": 256,
    "pids_limit": 32,
    "timeout_seconds": 60,
}


class SandboxViolation(DomainError):
    """Raised when plugin code uses a forbidden import or call."""


@runtime_checkable
class SandboxRuntime(Protocol):
    """The isolation backend (Docker+seccomp in M5; a mock in tests)."""

    def run(
        self,
        *,
        code: str,
        context: CaseContext,
        security: dict[str, Any],
        resource_limits: dict[str, Any],
    ) -> dict[str, Any]: ...


def static_check(code: str) -> None:
    """Statically reject forbidden imports/calls in plugin code (no execution)."""
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        raise SandboxViolation(f"plugin has invalid syntax: {exc}") from exc
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _reject_module(alias.name)
        elif isinstance(node, ast.ImportFrom):
            _reject_module(node.module or "")
        elif isinstance(node, ast.Call):
            _reject_call(node)


def _reject_module(name: str) -> None:
    root = name.split(".")[0]
    if root in FORBIDDEN_MODULES:
        raise SandboxViolation(f"plugin import of {name!r} is forbidden")


def _reject_call(node: ast.Call) -> None:
    func = node.func
    if isinstance(func, ast.Name) and func.id in FORBIDDEN_CALLS:
        raise SandboxViolation(f"plugin call to {func.id!r} is forbidden")
    if isinstance(func, ast.Attribute) and func.attr in {"system", "popen", "exec"}:
        raise SandboxViolation(f"plugin call to .{func.attr}() is forbidden")


class PythonPluginSandbox:
    """Scan a plugin statically, then run it inside the injected runtime."""

    def __init__(self, runtime: SandboxRuntime) -> None:
        self._runtime = runtime

    def execute(self, *, code: str, context: CaseContext) -> dict[str, Any]:
        """Static-check the plugin, then run it isolated; return its result."""
        static_check(code)  # raises SandboxViolation before anything executes
        return self._runtime.run(
            code=code,
            context=context,
            security=dict(SANDBOX_SECURITY_FLAGS),
            resource_limits=dict(DEFAULT_RESOURCE_LIMITS),
        )
