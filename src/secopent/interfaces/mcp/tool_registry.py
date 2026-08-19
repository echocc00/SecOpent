# src/secopent/interfaces/mcp/tool_registry.py
"""MCP tool registry: self-written orchestration tools + adopted trust levels (§13).

The MCP Server exposes two kinds of tools:

- **self-written** orchestration tools (project/scope/plan/assessment/asset/
  finding/intel/report) that bind to the deterministic Application Services;
- **adopted** external MCP servers (cve-mcp-server, mcp-security-hub), whose
  output is marked ``untrusted_external_mcp`` and never allowed to drive a
  deterministic decision.

Dangerous primitives (``shell`` / ``docker_run`` / ``execute_python`` / ``exec``
/ ``eval``) can NEVER be registered - the agent gets orchestration, not arbitrary
execution. The registry is framework-free so it is testable without the MCP SDK
(the SDK wraps these specs in M5); trust levels travel with each tool.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from secopent.domain.common.errors import DomainError

# The canonical self-written orchestration tools (six groups).
STANDARD_ORCHESTRATION_TOOLS: tuple[str, ...] = (
    # project / scope
    "project_create",
    "scope_draft",
    "scope_validate",
    "scope_freeze",
    # assessment / plan / execution
    "assessment_create",
    "plan_generate",
    "plan_approve",
    "assessment_start",
    "grant_list",
    "mission_create",
    "assessment_pause",
    "assessment_resume",
    "assessment_cancel",
    "assessment_status",
    # reasoning loop control (human-only at the service layer)
    "loop_pause",
    "loop_resume",
    # asset
    "asset_list",
    # finding / evidence
    "finding_list",
    "finding_validate",
    # intel
    "intel_search",
    # report
    "report_render",
)

# Tools that must never be exposed to the agent.
FORBIDDEN_TOOL_NAMES: frozenset[str] = frozenset(
    {"shell", "docker_run", "execute_python", "exec", "eval", "run_command", "subprocess"}
)


class ToolTrustLevel(StrEnum):
    """Trust classification carried by every MCP tool."""

    SELF_WRITTEN = "self_written"
    ADOPTED = "adopted_external_mcp"
    UNTRUSTED = "untrusted_external_mcp"


class ToolRegistrationError(DomainError):
    """Raised when registering a forbidden or duplicate tool."""


class ToolNotFoundError(DomainError):
    """Raised when invoking an unregistered tool."""


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """A registered MCP tool: identity + trust level + handler."""

    name: str
    description: str
    trust_level: ToolTrustLevel
    handler: Callable[..., object]


def _not_directly_callable(**_kwargs: object) -> object:
    raise ToolRegistrationError(
        "adopted external MCP tools are proxied, not called directly here"
    )


class McpToolRegistry:
    """Registry of MCP tools with trust levels and forbidden-name enforcement."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        """Register a tool; reject forbidden names and duplicates."""
        if spec.name in FORBIDDEN_TOOL_NAMES:
            raise ToolRegistrationError(
                f"tool {spec.name!r} is forbidden and cannot be exposed to the agent"
            )
        if spec.name in self._tools:
            raise ToolRegistrationError(f"tool {spec.name!r} already registered")
        self._tools[spec.name] = spec

    def register_self_written(
        self, name: str, description: str, handler: Callable[..., object]
    ) -> ToolSpec:
        spec = ToolSpec(name, description, ToolTrustLevel.SELF_WRITTEN, handler)
        self.register(spec)
        return spec

    def register_adopted(
        self, name: str, description: str, *, verified: bool = False
    ) -> ToolSpec:
        """Register an adopted external MCP tool, marked (un)trusted."""
        trust = ToolTrustLevel.ADOPTED if verified else ToolTrustLevel.UNTRUSTED
        spec = ToolSpec(name, description, trust, _not_directly_callable)
        self.register(spec)
        return spec

    def register_standard_tools(
        self, handlers: Mapping[str, Callable[..., object]]
    ) -> tuple[ToolSpec, ...]:
        """Register the canonical self-written tools for which handlers are given."""
        registered: list[ToolSpec] = []
        for name in STANDARD_ORCHESTRATION_TOOLS:
            handler = handlers.get(name)
            if handler is None:
                continue
            registered.append(
                self.register_self_written(name, f"Orchestration tool: {name}", handler)
            )
        return tuple(registered)

    def get(self, name: str) -> ToolSpec:
        spec = self._tools.get(name)
        if spec is None:
            raise ToolNotFoundError(f"tool not registered: {name}")
        return spec

    def invoke(self, __tool: str, **params: object) -> object:
        """Dispatch to a self-written tool's handler (adopted tools are proxied).

        ``__tool`` is positional-only so a tool whose own parameter is named
        ``name`` (e.g. ``project_create(name=...)``) does not collide with the
        routing argument.
        """
        spec = self.get(__tool)
        return spec.handler(**params)

    def names(self, trust_level: ToolTrustLevel | None = None) -> tuple[str, ...]:
        return tuple(
            sorted(
                name
                for name, spec in self._tools.items()
                if trust_level is None or spec.trust_level is trust_level
            )
        )

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)
