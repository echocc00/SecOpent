# src/secopent/interfaces/mcp/server.py
"""MCP transport wiring: FastMCP server (stdio + Streamable HTTP).

The ONLY module that imports the ``mcp`` SDK (the AST boundary guard allows
frameworks in ``interfaces/``). Two transports share the same tool set built
from ``TOOL_HANDLERS`` (handlers.py), which in turn bind to the exact
Application Services the API routers use:

- **stdio** (``secopent-mcp`` console script / ``python -m ...mcp.server``):
  standalone entrypoint. It calls ``create_app()`` - the single composition
  root - and reads ``app.state`` for the shared singletons (Database, signed
  AuditChain, scope enforcer), so there is ZERO duplicate composition: the
  stdio process and the API process build the identical dependency graph.
- **Streamable HTTP** (mounted at ``/mcp`` inside the existing FastAPI app):
  reuses the same ``app.state`` singletons in-process, so the agent talks to
  the exact same signed-audit/scope-enforced surface as the Web UI.

Stateless mode: ``FastMCP(..., stateless_http=True, streamable_http_path="/")``
builds a Starlette app whose single route is ``/``; mounting it at ``/mcp`` on
the host makes the endpoint ``http://host:8000/mcp``. Stateless HTTP means each
request is a self-contained transport (no client session-id), but the SDK's
session manager still needs its anyio task group initialized for the app's
lifetime - that is what ``McpHttpTransport.serve`` does from the host's
lifespan (see the class docstring; this also avoids the known "Task group is
not initialized" failure when embedding MCP into an existing ASGI app).

Safety: every tool is SELF_WRITTEN, ``FORBIDDEN_TOOL_NAMES`` still rejects
shell/docker/python/exec/eval, and the human-gated tools (``plan_approve`` /
``assessment_start``) return ``HUMAN_REQUIRED`` to the agent (never a scan
trigger).
"""
from __future__ import annotations

import functools
import inspect
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .handlers import TOOL_HANDLERS, McpRuntime


def _bind(handler: Callable[..., object], runtime: McpRuntime) -> Callable[..., object]:
    """Bind ``runtime`` to a typed handler, preserving name/doc/signature.

    FastMCP's tool registration introspects the callable it receives (it needs
    ``__name__`` and the parameter signature); a bare ``functools.partial``
    would break that (no ``__name__``). ``functools.wraps`` copies the
    metadata onto a closure, and the ``runtime`` parameter is dropped from a
    custom ``__signature__`` so the tool schema exposes exactly the agent's
    keyword arguments (``runtime`` is injected, never client-supplied).
    """
    _signature = inspect.signature(handler)
    params = [p for p in _signature.parameters.values() if p.name != "runtime"]
    _params_sig = _signature.replace(parameters=params)

    @functools.wraps(handler)
    def _bound(**kwargs: object) -> object:
        return handler(runtime, **kwargs)

    _bound.__signature__ = _params_sig  # type: ignore[attr-defined]
    return _bound


def _runtime_from_app(app: FastAPI) -> McpRuntime:
    """Read the shared singletons off an app built by ``create_app``."""
    from ..api.routers.assessments import _run_assessment_daemon, _run_resume_daemon

    def _schedule_resume(assessment_id: str) -> None:
        """Run the resume drain in the caller's (already spawned) thread."""
        st = app.state
        _run_resume_daemon(
            db=st.db,
            assessment_id=assessment_id,
            active_executions=getattr(st, "active_executions", None),
            active_executions_lock=getattr(st, "active_executions_lock", None),
            audit_chain=getattr(st, "audit_chain", None),
            oracle=getattr(st, "oracle", None),
            audit_outbox=getattr(st, "outbox_activation", {}).get("recorder"),
        )

    def _schedule_start(assessment_id: str) -> None:
        """Trigger a FULL new execution (grant path, v0.6.0).

        Mirrors the API /start background task exactly: the daemon owns its
        own UnitOfWork and reads every singleton off app.state, so the MCP
        grant path produces the identical execution as a human HTTP start.
        """
        st = app.state
        _run_assessment_daemon(
            db=st.db,
            assessment_id=assessment_id,
            active_executions=getattr(st, "active_executions", None),
            active_executions_lock=getattr(st, "active_executions_lock", None),
            emergency_stop=getattr(st, "emergency_stop", None),
            permit_signer=getattr(st, "permit_signer", None),
            permit_registry=getattr(st, "permit_registry", None),
            permit_verifier=getattr(st, "permit_verifier", None),
            scope_enforcer=getattr(st, "scope_enforcer", None),
            audit_chain=getattr(st, "audit_chain", None),
            egress_guard=getattr(st, "egress_guard", None),
            nft_scope_enforcer=getattr(st, "nft_scope_enforcer", None),
            netns_isolator=getattr(st, "netns_isolator", None),
            make_nft_enforcer=getattr(st, "make_nft_enforcer", None),
            oracle=getattr(st, "oracle", None),
            audit_outbox=getattr(st, "outbox_activation", {}).get("recorder"),
        )

    return McpRuntime(
        db=app.state.db,
        audit_chain=app.state.audit_chain,
        scope_enforcer=getattr(app.state, "scope_enforcer", None),
        resume_scheduler=_schedule_resume,
        start_scheduler=_schedule_start,
        llm_backend=getattr(app.state, "llm_backend", None),
    )


def build_mcp_server(runtime: McpRuntime) -> FastMCP:
    """Build the FastMCP server exposing the standard orchestration tools.

    Each tool is registered from the raw typed handler in ``handlers.py`` with
    ``runtime`` bound via ``functools.partial``, so FastMCP introspects the
    remaining keyword-only parameters into the tool's input schema (the
    registry's own invoke path binds the same handlers through lambdas).
    """
    mcp = FastMCP(
        "secopent",
        streamable_http_path="/",
        # Stateless: every request is a fresh transport with no session-id - a
        # request-per-call deterministic tool surface needs no client session
        # lifecycle, and it sidesteps the SDK's session-manager statefulness
        # when embedded in an existing ASGI app.
        stateless_http=True,
        # The SDK auto-enables DNS-rebinding host validation (with an EMPTY
        # allowlist) whenever the host is localhost, rejecting every Host
        # header with 421. Deployment hosts vary, and the existing API surface
        # performs no Host validation either - so the protection is disabled
        # explicitly (internal-network trust; see docs/architecture/interfaces.md).
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=False
        ),
    )
    for name, handler in TOOL_HANDLERS.items():
        description = inspect.getdoc(handler) or f"Orchestration tool: {name}"
        mcp.tool(name, description=description)(_bind(handler, runtime))
    return mcp


def streamable_http_app(app: FastAPI) -> Any:
    """Starlette ASGI app for the Streamable HTTP transport, mounted at /mcp.

    Note: the returned app's session manager is NOT initialized until the
    host's lifespan enters ``McpHttpTransport.serve`` - see that class. This
    helper is kept for direct (non-embedded) serving/testing.
    """
    return build_mcp_server(_runtime_from_app(app)).streamable_http_app()


class McpHttpTransport:
    """Streamable HTTP transport mountable inside the existing FastAPI app.

    The MCP SDK's ``StreamableHTTPSessionManager`` creates its anyio task
    group only inside ``manager.run()``, which can be entered ONCE per
    manager instance - exactly the shape of an ASGI host's lifespan. The
    SDK's own docstring for ``run()`` recommends the lifespan pattern.

    Because TestClients / restarts may re-run a lifespan on the same app
    instance, this transport rebuilds the FastMCP server (fresh manager) on
    EVERY ``serve()`` entry and swaps the being-served ASGI app behind a fixed
    mount point: the mounted proxy is stable at create_app time, and each
    lifespan entry provides a fresh, correct manager. Requests received
    while no lifespan is active get a 503 (never a stale-manager crash).
    """
    def __init__(self) -> None:
        self._inner: Callable[..., object] | None = None

    async def __call__(self, scope: object, receive: object, send: object) -> None:
        inner = self._inner
        if inner is None:
            from starlette.responses import Response

            response = Response(
                b"MCP server not initialized (no active lifespan)",
                status_code=503,
                media_type="text/plain",
            )
            # Internal API; called by the framework with the ASGI triple.
            await response(scope, receive, send)  # type: ignore[arg-type]
            return
        await inner(scope, receive, send)  # type: ignore[misc]

    @asynccontextmanager
    async def serve(self, runtime: McpRuntime) -> AsyncIterator[None]:
        """Start serving: rebuild FastMCP + initialize its session manager.

        Entered from the host app's lifespan; yields for the app's lifetime,
        then cleans up so a restart (fresh ``serve``) builds a new manager.
        """
        mcp = build_mcp_server(runtime)
        # streamable_http_app() lazily creates the session manager and binds
        # the ASGI app to it; only then can run() initialize its task group.
        self._inner = mcp.streamable_http_app()
        manager = getattr(mcp, "_session_manager", None)
        if manager is None:  # pragma: no cover - streamable_http_app() creates it
            raise RuntimeError("FastMCP session manager not created")
        try:
            async with manager.run():
                yield
        finally:
            self._inner = None


def main() -> None:
    """stdio entrypoint (``secopent-mcp`` console script / ``python -m``).

    Reuses ``create_app`` - the Web/API composition root - so the stdio
    process shares the identical dependency graph (DB, signing, permit,
    signed audit chain, scope enforcement). Note: running this against the
    same SQLite file as a live API process follows the single-writer
    convention; production should point both at PostgreSQL
    (``SECOPTENT_DB_URL``).
    """
    from ..api.main import create_app

    app = create_app()
    runtime = _runtime_from_app(app)
    build_mcp_server(runtime).run(transport="stdio")


if __name__ == "__main__":
    main()