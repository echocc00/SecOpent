# tests/interfaces/test_mcp_tool_registry.py
"""Phase 2.9: MCP tool registry wiring + safe-tool-surface guard.

Asserts that:
(a) the registry mounts on ``app.state.mcp_tool_registry`` (both the root app
    and the ``/api`` sub-app share the same instance);
(b) no registered tool name contains a dangerous primitive
    (shell/docker/python/exec/eval) - the M4 DoD "MCP 不暴露 shell/docker/
    python" enforced as a substring guard over the live registry, not just
    the static ``FORBIDDEN_TOOL_NAMES`` set; and
(c) at least one read-only tool is registered (the safe surface is non-empty).
"""
from __future__ import annotations

import pytest

from secopent.interfaces.api.main import create_app
from secopent.interfaces.mcp import (
    FORBIDDEN_TOOL_NAMES,
    SAFE_READ_ONLY_TOOLS,
    McpToolRegistry,
    build_default_registry,
)

# Substrings that must never appear in any registered tool name. This is a
# defence-in-depth guard on top of FORBIDDEN_TOOL_NAMES: even if a future
# tool were named "execute_python_script" the substring check would catch it
# before the agent could reach it.
_DANGEROUS_SUBSTRINGS: tuple[str, ...] = (
    "shell",
    "docker",
    "python",
    "exec",
    "eval",
    "subprocess",
    "run_command",
)


class TestRegistryMounts:
    def test_registry_mounted_on_app_state(self) -> None:
        app = create_app()
        registry = getattr(app.state, "mcp_tool_registry", None)
        assert isinstance(registry, McpToolRegistry)
        assert len(registry) > 0

    def test_registry_shared_with_api_subapp(self) -> None:
        app = create_app()
        root_registry = app.state.mcp_tool_registry
        # The /api sub-app is mounted under app.routes; reach its state by
        # locating the mounted Starlette/FastAPI sub-application.
        api_subapp = next(
            r.app for r in app.routes if getattr(r, "path", "") == "/api"
        )
        assert api_subapp.state.mcp_tool_registry is root_registry


class TestSafeSurfaceGuard:
    def test_no_tool_name_contains_dangerous_substring(self) -> None:
        registry = build_default_registry()
        names = registry.names()
        assert names, "registry must register at least one tool"
        for name in names:
            lowered = name.lower()
            for sub in _DANGEROUS_SUBSTRINGS:
                assert sub not in lowered, (
                    f"tool name {name!r} contains forbidden substring {sub!r}"
                )

    def test_forbidden_tools_cannot_be_registered(self) -> None:
        registry = build_default_registry()
        for name in FORBIDDEN_TOOL_NAMES:
            with pytest.raises(Exception):  # noqa: B017 - register raises ToolRegistrationError
                registry.register_self_written(name, "x", lambda: None)

    def test_at_least_one_read_only_tool_registered(self) -> None:
        registry = build_default_registry()
        names = set(registry.names())
        # The safe read-only surface must be present.
        assert set(SAFE_READ_ONLY_TOOLS).issubset(names)
        # And every safe tool is self-written (read-only, deterministic).
        for name in SAFE_READ_ONLY_TOOLS:
            spec = registry.get(name)
            assert spec.trust_level.value == "self_written"


class TestReadOnlyHandlersAreSideEffectFree:
    """The safe surface returns deterministic empty results when no adapter
    is wired - proving the tools are read-only and mount-safe."""

    def test_list_findings_returns_empty_when_no_repo(self) -> None:
        registry = build_default_registry()
        assert registry.invoke("list_findings", assessment_id="a1") == []

    def test_get_finding_returns_none_when_no_repo(self) -> None:
        registry = build_default_registry()
        assert registry.invoke("get_finding", finding_id="f1") is None

    def test_list_required_classes_returns_empty_when_no_catalog(self) -> None:
        registry = build_default_registry()
        assert registry.invoke("list_required_classes", asset_type="web_app") == []
