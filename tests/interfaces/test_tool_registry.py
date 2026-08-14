"""TDD tests for the MCP tool registry (M4 Task 5, §13 + ADR-007)."""
from __future__ import annotations

import pytest

from secopent.interfaces.mcp.tool_registry import (
    STANDARD_ORCHESTRATION_TOOLS,
    McpToolRegistry,
    ToolNotFoundError,
    ToolRegistrationError,
    ToolSpec,
    ToolTrustLevel,
)


def test_standard_tools_are_the_six_groups() -> None:
    assert "project_create" in STANDARD_ORCHESTRATION_TOOLS
    assert "scope_freeze" in STANDARD_ORCHESTRATION_TOOLS
    assert "plan_generate" in STANDARD_ORCHESTRATION_TOOLS
    assert "assessment_start" in STANDARD_ORCHESTRATION_TOOLS
    assert "grant_list" in STANDARD_ORCHESTRATION_TOOLS  # v0.6.0
    assert "assessment_create" in STANDARD_ORCHESTRATION_TOOLS
    assert "finding_validate" in STANDARD_ORCHESTRATION_TOOLS
    assert "report_render" in STANDARD_ORCHESTRATION_TOOLS
    assert len(STANDARD_ORCHESTRATION_TOOLS) == 18


def test_register_self_written_and_invoke() -> None:
    registry = McpToolRegistry()
    registry.register_self_written("asset_list", "list assets", lambda: ["a", "b"])
    spec = registry.get("asset_list")
    assert spec.trust_level is ToolTrustLevel.SELF_WRITTEN
    assert registry.invoke("asset_list") == ["a", "b"]


@pytest.mark.parametrize("name", ["shell", "docker_run", "execute_python", "eval"])
def test_forbidden_tools_cannot_be_registered(name: str) -> None:
    registry = McpToolRegistry()
    with pytest.raises(ToolRegistrationError):
        registry.register_self_written(name, "dangerous", lambda: None)


def test_forbidden_via_generic_register_rejected() -> None:
    registry = McpToolRegistry()
    spec = ToolSpec("shell", "x", ToolTrustLevel.SELF_WRITTEN, lambda: None)
    with pytest.raises(ToolRegistrationError):
        registry.register(spec)


def test_register_standard_tools_dispatches() -> None:
    registry = McpToolRegistry()
    calls: list[str] = []
    handlers = {
        "assessment_start": lambda assessment_id="": calls.append("start") or "started",
        "report_render": lambda: calls.append("render") or "report",
    }
    registered = registry.register_standard_tools(handlers)
    assert {s.name for s in registered} == {"assessment_start", "report_render"}
    assert registry.invoke("assessment_start") == "started"
    assert registry.invoke("report_render") == "report"


def test_adopted_tool_trust_levels() -> None:
    registry = McpToolRegistry()
    untrusted = registry.register_adopted("cve_lookup", "CVE search")
    trusted = registry.register_adopted("security_hub", "hub", verified=True)
    assert untrusted.trust_level is ToolTrustLevel.UNTRUSTED
    assert trusted.trust_level is ToolTrustLevel.ADOPTED


def test_adopted_tool_not_directly_callable() -> None:
    registry = McpToolRegistry()
    registry.register_adopted("cve_lookup", "CVE search")
    with pytest.raises(ToolRegistrationError):
        registry.invoke("cve_lookup", cve="CVE-2021-1234")


def test_duplicate_registration_rejected() -> None:
    registry = McpToolRegistry()
    registry.register_self_written("asset_list", "x", lambda: None)
    with pytest.raises(ToolRegistrationError):
        registry.register_self_written("asset_list", "y", lambda: None)


def test_names_filter_by_trust_level() -> None:
    registry = McpToolRegistry()
    registry.register_self_written("asset_list", "x", lambda: None)
    registry.register_adopted("cve_lookup", "y")
    assert registry.names(ToolTrustLevel.SELF_WRITTEN) == ("asset_list",)
    assert registry.names(ToolTrustLevel.UNTRUSTED) == ("cve_lookup",)
    assert set(registry.names()) == {"asset_list", "cve_lookup"}


def test_invoke_unknown_raises() -> None:
    with pytest.raises(ToolNotFoundError):
        McpToolRegistry().invoke("missing")
