"""TDD tests for the Python plugin sandbox (M2 Task 9, §11.4 seccomp isolation).

The sandbox statically rejects plugins that import forbidden modules or make
forbidden calls BEFORE anything executes; benign plugins run through an injected
runtime that receives the §11.4 container hardening flags. The CaseContext SDK
is the only surface a plugin gets - credentials come back as reference handles,
never raw secrets. Docker/seccomp are M5; the runtime is a mock here.
"""
from __future__ import annotations

from typing import Any

import pytest

from secopent.infrastructure.sandbox.case_context import (
    CapabilityNotGranted,
    CaseContext,
)
from secopent.infrastructure.sandbox.python_sandbox import (
    SANDBOX_SECURITY_FLAGS,
    PythonPluginSandbox,
    SandboxRuntime,
    SandboxViolation,
    static_check,
)

_BENIGN = """
resp = ctx.scoped_http("GET", "https://x.test/")
ctx.emit_observation(title="ok")
"""


class RecordingRuntime:
    def __init__(self, result: dict[str, Any] | None = None) -> None:
        self._result = result or {"ok": True}
        self.calls: list[dict[str, Any]] = []

    def run(
        self,
        *,
        code: str,
        context: CaseContext,
        security: dict[str, Any],
        resource_limits: dict[str, Any],
    ) -> dict[str, Any]:
        self.calls.append(
            {"code": code, "security": security, "resource_limits": resource_limits}
        )
        return self._result


# ---------------------------------------------------------------------------
# static_check
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code",
    [
        "import subprocess",
        "import os",
        "from socket import socket",
        "import docker",
        "eval('1+1')",
        "exec('x=1')",
        "open('/etc/passwd')",
        "os.system('id')",
    ],
)
def test_static_check_rejects_forbidden(code: str) -> None:
    with pytest.raises(SandboxViolation):
        static_check(code)


def test_static_check_accepts_benign() -> None:
    static_check(_BENIGN)  # no raise


# ---------------------------------------------------------------------------
# PythonPluginSandbox.execute
# ---------------------------------------------------------------------------


def test_execute_runs_benign_plugin() -> None:
    runtime = RecordingRuntime()
    sandbox = PythonPluginSandbox(runtime)
    result = sandbox.execute(code=_BENIGN, context=CaseContext())
    assert result == {"ok": True}
    assert len(runtime.calls) == 1


def test_execute_passes_hardening_flags() -> None:
    runtime = RecordingRuntime()
    PythonPluginSandbox(runtime).execute(code=_BENIGN, context=CaseContext())
    security = runtime.calls[0]["security"]
    assert security["read_only"] is True
    assert security["non_root"] is True
    assert security["cap_drop_all"] is True
    assert security["no_new_privileges"] is True
    assert security["host_network"] is False
    assert security["docker_socket"] is False
    assert security == SANDBOX_SECURITY_FLAGS


def test_execute_rejects_bad_plugin_without_running() -> None:
    runtime = RecordingRuntime()
    sandbox = PythonPluginSandbox(runtime)
    with pytest.raises(SandboxViolation):
        sandbox.execute(code="import subprocess", context=CaseContext())
    assert runtime.calls == [], "runtime executed despite static rejection"


def test_runtime_satisfies_protocol() -> None:
    assert isinstance(RecordingRuntime(), SandboxRuntime)


# ---------------------------------------------------------------------------
# CaseContext SDK
# ---------------------------------------------------------------------------


def test_scoped_http_delegates_to_granted_capability() -> None:
    seen: list[dict[str, Any]] = []

    def http(*, method: str, url: str, **kw: Any) -> dict[str, Any]:
        seen.append({"method": method, "url": url})
        return {"status": 200}

    ctx = CaseContext(http=http)
    assert ctx.scoped_http("GET", "https://x.test/") == {"status": 200}
    assert seen[0] == {"method": "GET", "url": "https://x.test/"}


def test_unganted_capability_raises() -> None:
    ctx = CaseContext()  # no http granted
    with pytest.raises(CapabilityNotGranted):
        ctx.scoped_http("GET", "https://x.test/")


def test_credential_ref_never_returns_raw_secret() -> None:
    ctx = CaseContext(credentials={"api_key": "SUPER-SECRET-VALUE"})
    ref = ctx.credential_ref("api_key")
    assert ref == "credential-ref:api_key"
    assert "SUPER-SECRET-VALUE" not in ref


def test_credential_ref_unknown_raises() -> None:
    ctx = CaseContext(credentials={})
    with pytest.raises(CapabilityNotGranted):
        ctx.credential_ref("missing")


def test_emit_observation_collects() -> None:
    ctx = CaseContext()
    ctx.emit_observation(title="sqli", severity="high")
    assert ctx.observations == [{"title": "sqli", "severity": "high"}]
