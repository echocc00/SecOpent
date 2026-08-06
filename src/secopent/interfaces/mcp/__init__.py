# src/secopent/interfaces/mcp/__init__.py
"""MCP interface package: tool registry + safe default surface.

The MCP tool registry (§13 + ADR-007) exposes two kinds of tools to the agent:

- **self-written** orchestration tools that bind to deterministic Application
  Services (registered by ``build_default_registry`` for the read-only subset
  that has a stable handler today); and
- **adopted** external MCP servers (cve-mcp-server, mcp-security-hub), marked
  ``untrusted_external_mcp`` and never allowed to drive a deterministic
  decision.

Dangerous primitives (``shell`` / ``docker_run`` / ``execute_python`` /
``exec`` / ``eval``) can NEVER be registered - ``FORBIDDEN_TOOL_NAMES``
rejects them at ``register`` time (M4 DoD: "MCP 不暴露 shell/docker/python").
``build_default_registry`` only registers read-only query handlers; mutating
orchestration tools (plan_generate, assessment_start, ...) are wired in a
later phase once their Application Service signatures stabilize.
"""
from __future__ import annotations

from collections.abc import Mapping

from .tool_registry import (
    FORBIDDEN_TOOL_NAMES,
    STANDARD_ORCHESTRATION_TOOLS,
    McpToolRegistry,
    ToolNotFoundError,
    ToolRegistrationError,
    ToolSpec,
    ToolTrustLevel,
)

__all__ = [
    "FORBIDDEN_TOOL_NAMES",
    "STANDARD_ORCHESTRATION_TOOLS",
    "SAFE_READ_ONLY_TOOLS",
    "ToolNotFoundError",
    "ToolRegistrationError",
    "ToolSpec",
    "ToolTrustLevel",
    "build_default_registry",
]


def _list_findings(
    *,
    assessment_id: str = "",
    status: str = "",
    repository: Mapping[str, object] | None = None,
) -> object:
    """Read-only finding query. Returns a list (empty when no repo wired).

    The handler is intentionally permissive: the registry is framework-free
    and mountable without a live DB session. When ``repository`` is None the
    handler returns an empty list - the agent still sees a deterministic,
    safe response and the tool is provably read-only.
    """
    if repository is None:
        return []
    finder = repository.get("findings")
    if finder is None:
        return []
    if callable(finder):
        return finder(assessment_id=assessment_id, status=status)
    if isinstance(finder, list | tuple):
        return list(finder)
    return []


def _get_finding(
    *,
    finding_id: str = "",
    repository: Mapping[str, object] | None = None,
) -> object:
    """Read-only single-finding lookup. Returns None when not found."""
    if repository is None or not finding_id:
        return None
    getter = repository.get("get_finding")
    if callable(getter):
        return getter(finding_id=finding_id)
    return None


def _list_required_classes(
    *,
    asset_type: str = "",
    catalog: Mapping[str, object] | None = None,
) -> object:
    """Read-only catalog query. Returns the required test classes for an asset.

    Returns an empty list when no catalog is wired - the agent sees a stable
    safe surface and the tool is provably read-only.
    """
    if catalog is None:
        return []
    lookup = catalog.get("required_classes")
    if callable(lookup):
        return lookup(asset_type=asset_type)
    classes = catalog.get("classes", ())
    if isinstance(classes, list | tuple):
        return list(classes)
    return []


# The safe read-only surface: deterministic query handlers the agent may call
# without any risk of side effects. None of these touch shell/docker/python.
SAFE_READ_ONLY_TOOLS: tuple[str, ...] = (
    "list_findings",
    "get_finding",
    "list_required_classes",
)


def build_default_registry(
    *,
    repository: Mapping[str, object] | None = None,
    catalog: Mapping[str, object] | None = None,
) -> McpToolRegistry:
    """Build the default MCP tool registry with the safe read-only surface.

    Only read-only query tools are wired here (Phase 2.9). Mutating
    orchestration tools (plan_generate, assessment_start, ...) land in a
    later phase once their Application Service signatures are stable; the
    registry is already structured to accept them via
    ``register_standard_tools``.

    ``repository`` / ``catalog`` are optional injected adapters (Mappings of
    callable query handlers). When None, the tools return empty results -
    the registry still mounts and is provably read-only.
    """
    registry = McpToolRegistry()
    ctx_repo = repository
    ctx_catalog = catalog

    registry.register_self_written(
        "list_findings",
        "Read-only: list findings for an assessment (optionally filtered by status).",
        lambda **kw: _list_findings(repository=ctx_repo, **kw),
    )
    registry.register_self_written(
        "get_finding",
        "Read-only: fetch a single finding by id.",
        lambda **kw: _get_finding(repository=ctx_repo, **kw),
    )
    registry.register_self_written(
        "list_required_classes",
        "Read-only: list required test classes for an asset type from the catalog.",
        lambda **kw: _list_required_classes(catalog=ctx_catalog, **kw),
    )
    return registry
