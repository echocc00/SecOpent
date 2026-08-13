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
from typing import TYPE_CHECKING

from .tool_registry import (
    FORBIDDEN_TOOL_NAMES,
    STANDARD_ORCHESTRATION_TOOLS,
    McpToolRegistry,
    ToolNotFoundError,
    ToolRegistrationError,
    ToolSpec,
    ToolTrustLevel,
)

if TYPE_CHECKING:
    from .handlers import McpRuntime

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
    runtime: McpRuntime | None = None,
    repository: Mapping[str, object] | None = None,
    catalog: Mapping[str, object] | None = None,
) -> McpToolRegistry:
    """Build the MCP tool registry.

    Two wiring modes:

    - ``runtime=None`` (default): the legacy safe read-only surface
      (list_findings / get_finding / list_required_classes) with permissive
      handlers that accept optional ``repository``/``catalog`` Mappings and
      return deterministic empty results when nothing is wired. The registry
      stays framework-free and mount-safe (existing tests rely on this).
    - ``runtime=<McpRuntime>`` (``app.state`` wiring): ALL 17 standard
      orchestration tools are registered with real Application-Service
      handlers from ``handlers.py``, plus the 3 read-only tools bound to real
      repositories. Trust levels stay ``SELF_WRITTEN`` for every tool;
      ``FORBIDDEN_TOOL_NAMES`` still rejects shell/docker/python/exec/eval.

    ``repository`` / ``catalog`` remain accepted only in the legacy mode.
    """
    from .handlers import TOOL_HANDLERS

    registry = McpToolRegistry()
    if runtime is None:
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

    # Runtime-wired mode: every handler opens its own short-lived session from
    # runtime.db (commit-on-success / rollback-on-error), mirrors the API
    # routers, and records mutating actions on the signed AuditChain.
    bound = {
        name: (lambda _h=h, **kw: _h(runtime, **kw))
        for name, h in TOOL_HANDLERS.items()
    }
    registry.register_standard_tools(bound)
    registry.register_self_written(
        "list_findings",
        "Read-only: list findings for an assessment (optionally filtered).",
        lambda **kw: _list_findings_runtime(runtime, **kw),
    )
    registry.register_self_written(
        "get_finding",
        "Read-only: fetch a single finding by id.",
        lambda **kw: _get_finding_runtime(runtime, **kw),
    )
    registry.register_self_written(
        "list_required_classes",
        "Read-only: list required test classes for an asset type from the catalog.",
        lambda **kw: _list_required_classes_runtime(runtime, **kw),
    )
    return registry


def _list_findings_runtime(
    runtime: McpRuntime, *, assessment_id: str = "", status: str = ""
) -> object:
    """Read-only finding list against the real repository (runtime mode)."""
    from ...infrastructure.repositories.sqlalchemy_findings import (
        SqlAlchemyFindingRepository,
    )

    with runtime.db.unit_of_work() as uow:
        session = uow.session
        findings = SqlAlchemyFindingRepository(session).all(
            assessment_id=assessment_id or None, severity=None,
            oracle_verdict=None,
        )
        return [
            {
                "id": f.id,
                "title": f.title,
                "asset": f.asset,
                "severity": f.severity.value,
                "status": f.status.value,
                "assessment_id": f.assessment_id,
                "oracle_verdict": f.oracle_verdict.value,
            }
            for f in findings
            if not status or f.status.value == status
        ]


def _get_finding_runtime(
    runtime: McpRuntime, *, finding_id: str = ""
) -> object:
    """Read-only single-finding lookup against the real repository."""
    from ...infrastructure.repositories.sqlalchemy_findings import (
        SqlAlchemyFindingRepository,
    )

    if not finding_id:
        return None
    with runtime.db.unit_of_work() as uow:
        session = uow.session
        finding = SqlAlchemyFindingRepository(session).get(finding_id)
        if finding is None:
            return None
        return {
            "id": finding.id,
            "title": finding.title,
            "asset": finding.asset,
            "severity": finding.severity.value,
            "status": finding.status.value,
            "assessment_id": finding.assessment_id,
            "oracle_verdict": finding.oracle_verdict.value,
        }


def _list_required_classes_runtime(
    runtime: McpRuntime, *, asset_type: str = ""
) -> object:
    """Read-only catalog query against the real repository."""
    from ...domain.catalog.models import AssetType
    from ...infrastructure.repositories.sqlalchemy_catalog import (
        SqlAlchemyCatalogRepository,
    )

    if not asset_type:
        return []
    with runtime.db.unit_of_work() as uow:
        session = uow.session
        catalog = SqlAlchemyCatalogRepository(session).latest_catalog()
        if catalog is None:
            return []
        try:
            classes = catalog.required_for(AssetType(asset_type))
        except ValueError:
            return []
        return [
            {
                "id": c.id,
                "cwe": list(c.cwe),
                "owasp": list(c.owasp),
                "risk": c.risk.value,
            }
            for c in classes
        ]
