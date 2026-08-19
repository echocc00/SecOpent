# tests/interfaces/test_loop_mcp_server.py
"""Server-level registration test for the loop MCP tools (v0.7.8 Task 4).

Builds the real FastMCP server via ``build_mcp_server`` (the same ``TOOL_HANDLERS``
entry-point the transport uses) and asserts the four new loop tools are exposed
to the agent with the correct names — and are NOT in the forbidden set.
"""
from __future__ import annotations

import asyncio

from secopent.interfaces.api.main import create_app
from secopent.interfaces.mcp import STANDARD_ORCHESTRATION_TOOLS
from secopent.interfaces.mcp.server import _runtime_from_app, build_mcp_server


def _tool_names(mcp) -> set[str]:  # noqa: ANN001
    async def _list() -> list:
        return await mcp.list_tools()

    return {tool.name for tool in asyncio.run(_list())}


def test_build_mcp_server_exposes_loop_tools() -> None:
    app = create_app()
    mcp = build_mcp_server(_runtime_from_app(app))
    names = _tool_names(mcp)

    for tool in ("loop_status", "loop_history", "loop_create", "loop_stop"):
        assert tool in names, f"{tool} not exposed by the MCP server"
        assert tool in STANDARD_ORCHESTRATION_TOOLS


def test_loop_tools_not_forbidden() -> None:
    from secopent.interfaces.mcp.tool_registry import FORBIDDEN_TOOL_NAMES

    for tool in ("loop_status", "loop_history", "loop_create", "loop_stop"):
        assert tool not in FORBIDDEN_TOOL_NAMES
