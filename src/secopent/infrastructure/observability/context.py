# src/secopent/infrastructure/observability/context.py
"""Per-request logging context: request_id + tenant bound to structlog (T16).

A FastAPI middleware that, for each request, binds a ``request_id`` (from the
``X-Request-Id`` header or a fresh UUID) and a ``tenant`` (from ``X-Tenant``,
default ``default``) into structlog's contextvars. Because ``configure_logging``
includes ``merge_contextvars``, every log emitted while handling the request
carries these fields; the response echoes ``X-Request-Id`` for correlation.
"""
from __future__ import annotations

import uuid

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import Response
from starlette.middleware.base import RequestResponseEndpoint


def install_request_context(app: FastAPI) -> None:
    """Register the request-context middleware on ``app``."""

    @app.middleware("http")
    async def _bind_request_context(
        request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        tenant = request.headers.get("x-tenant") or "default"
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id, tenant=tenant)
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        return response
