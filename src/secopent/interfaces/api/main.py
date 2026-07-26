# src/secopent/interfaces/api/main.py
"""FastAPI OpenAPI surface (§13): command/query separation, idempotency, SSE.

A focused API demonstrating the M4 contract:
- **command/query separation**: POST mutates, GET reads;
- **idempotency**: a repeated POST with the same ``Idempotency-Key`` returns the
  original response instead of creating a duplicate;
- **long-task SSE**: ``/assessments/{id}/events`` streams status as
  ``text/event-stream``;
- standard error codes (404 for unknown resources, 422 for invalid payloads).

The app is a factory (``create_app``) so tests get an isolated instance with an
in-memory store; the production app wires the SqlAlchemy repositories.
"""
from __future__ import annotations

import json
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.engine import Engine

from ...infrastructure.db.session import Database
from ...infrastructure.db.sqlite import create_sqlite_engine
from .routers import assessments_router, projects_router, scopes_router


class FindingIn(BaseModel):
    """Command payload to create a finding."""

    title: str
    asset: str
    severity: str = "medium"
    cwe: list[str] = []


class FindingOut(BaseModel):
    """Query representation of a finding."""

    id: str
    title: str
    asset: str
    severity: str
    cwe: list[str]


def create_app(engine: Engine | None = None) -> FastAPI:
    """Build an API instance.

    ``engine`` is the SQLAlchemy engine to bind; when omitted a temporary
    SQLite engine is created (for tests / lightweight runs). Resource routers
    (projects/scopes/assessments) are DB-backed via ``app.state.db``; the
    findings/health/SSE endpoints below remain in-memory demonstrations.
    """
    app = FastAPI(title="SecOpent API", version="0.1.0")
    if engine is None:
        engine = create_sqlite_engine(Path(tempfile.mktemp(suffix=".db")))
    app.state.db = Database(engine)

    # Resource routers (DB-backed).
    app.include_router(projects_router)
    app.include_router(scopes_router)
    app.include_router(assessments_router)

    findings: dict[str, dict[str, Any]] = {}
    idempotency: dict[str, dict[str, Any]] = {}
    counter = {"n": 0}

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/findings", status_code=201, response_model=FindingOut)
    def create_finding(
        payload: FindingIn,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        # Idempotent replay: same key -> original response, no duplicate.
        if idempotency_key is not None and idempotency_key in idempotency:
            return idempotency[idempotency_key]
        counter["n"] += 1
        finding: dict[str, Any] = {
            "id": f"finding-{counter['n']}",
            "title": payload.title,
            "asset": payload.asset,
            "severity": payload.severity,
            "cwe": list(payload.cwe),
        }
        findings[finding["id"]] = finding
        if idempotency_key is not None:
            idempotency[idempotency_key] = finding
        return finding

    @app.get("/findings", response_model=list[FindingOut])
    def list_findings() -> list[dict[str, Any]]:
        return list(findings.values())

    @app.get("/findings/{finding_id}", response_model=FindingOut)
    def get_finding(finding_id: str) -> dict[str, Any]:
        finding = findings.get(finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="finding not found")
        return finding

    @app.get("/assessments/{assessment_id}/events")
    def assessment_events(assessment_id: str) -> StreamingResponse:
        """Stream assessment status as server-sent events (long task)."""

        def _stream() -> Iterator[str]:
            for status in ("queued", "running", "completed"):
                event = {"assessment_id": assessment_id, "status": status}
                yield f"data: {json.dumps(event)}\n\n"
                time.sleep(0)

        return StreamingResponse(_stream(), media_type="text/event-stream")

    return app
