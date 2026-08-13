"""Interfaces: MCP Streamable HTTP transport mounted at /mcp (MCP §13).

Drives the mounted endpoint through TestClient (lifespan starts the FastMCP
session manager via ``McpHttpTransport.serve``) with raw JSON-RPC messages -
the client-side protocol the official MCP SDK speaks.

Covers: initialize handshake, tools/list (17 standard tools), a read-only
tools/call, the HUMAN_REQUIRED mapping over HTTP, and the no-307 direct /mcp
endpoint.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient

from secopent.interfaces.api.main import create_app

# Streamable HTTP requires the client to accept both media types.
_ACCEPT = "application/json, text/event-stream"


def _parse_sse(text: str) -> dict[str, Any]:
    """Parse an SSE response body into the JSON-RPC payload (data: lines)."""
    data_lines = [
        line[5:].strip()
        for line in text.splitlines()
        if line.startswith("data:")
    ]
    assert data_lines, "no data: lines in SSE response"
    body = "\n".join(data_lines)
    return json.loads(body)


def _call(
    client: TestClient,
    method: str,
    params: dict[str, Any] | None = None,
    sid: str | None = None,
) -> dict[str, Any]:
    headers = {"Accept": _ACCEPT}
    if sid:
        headers["mcp-session-id"] = sid
    payload = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        payload["params"] = params
    response = client.post("/mcp", headers=headers, json=payload)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/event-stream")
    return _parse_sse(response.text)


def _initialize(client: TestClient) -> tuple[dict[str, Any], str | None]:
    result = _call(client, "initialize", {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "secopent-tests", "version": "0"},
    })
    assert result["id"] == 1
    assert result["result"]["serverInfo"]["name"] == "secopent"
    return result, result.get("sessionId") or None


def test_mcp_http_endpoint_serves_without_redirect() -> None:
    """POST /mcp reaches the transport directly (no 307 -> /mcp/)."""
    with TestClient(create_app()) as client:
        headers = {"Accept": _ACCEPT}
        response = client.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
        })
        assert response.status_code == 200, response.text
        assert response.headers.get("location") is None


def test_initialize_and_tools_list() -> None:
    with TestClient(create_app()) as client:
        _result, sid = _initialize(client)
        listed = _call(client, "tools/list", {}, sid=sid)
        tools = listed["result"]["tools"]
        names = {t["name"] for t in tools}
        assert len(tools) >= 17
        assert "assessment_status" in names
        assert "plan_generate" in names
        assert "assessment_create" in names
        # The human-gated tools are still VISIBLE to the agent (they must learn
        # a human is required), not hidden.
        assert "plan_approve" in names
        assert "assessment_start" in names


def test_tools_call_read_only_over_http() -> None:
    with TestClient(create_app()) as client:
        _result, sid = _initialize(client)
        called = _call(client, "tools/call", {
            "name": "assessment_status",
            "arguments": {"assessment_id": "nope"},
        }, sid=sid)
        text = called["result"]["content"][0]["text"]
        payload = json.loads(text)
        assert payload["status"] == "error"
        assert payload["code"] == "NOT_FOUND"


def test_tools_call_project_create_over_http() -> None:
    with TestClient(create_app()) as client:
        _result, sid = _initialize(client)
        called = _call(client, "tools/call", {
            "name": "project_create",
            "arguments": {"name": "http-demo"},
        }, sid=sid)
        text = called["result"]["content"][0]["text"]
        payload = json.loads(text)
        assert payload["id"].startswith("proj-")
        assert payload["name"] == "http-demo"


def test_human_gate_over_http() -> None:
    with TestClient(create_app()) as client:
        _result, sid = _initialize(client)
        called = _call(client, "tools/call", {
            "name": "plan_approve",
            "arguments": {"assessment_id": "asm-x"},
        }, sid=sid)
        text = called["result"]["content"][0]["text"]
        payload = json.loads(text)
        assert payload["status"] == "HUMAN_REQUIRED"


def test_requests_outside_lifespan_get_503_only_after_transport_reset() -> None:
    """After the lifespan exits, the proxy returns 503 (never a stale crash).

    A fresh app (lifespan not entered) must still build and mount.
    """
    app = create_app()
    client = TestClient(app)
    # No context manager: lifespan never ran, requests are 503 with a clear
    # message instead of a manager crash.
    response = client.post("/mcp", headers={"Accept": _ACCEPT}, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    assert response.status_code == 503