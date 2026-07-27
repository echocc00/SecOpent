# src/secopent/interfaces/api/main.py
"""FastAPI OpenAPI surface (§13): command/query separation, idempotency, SSE.

The app is a factory (``create_app``) so tests get an isolated instance.
Resource routers (projects/scopes/assessments/tools/findings/intel/updates/
audit) are DB-backed via ``app.state.db``; the health + long-task SSE endpoints
below remain lightweight demonstrations of the M4 contract.

- **command/query separation**: POST mutates, GET reads;
- **idempotency**: a repeated POST with the same ``Idempotency-Key`` returns the
  original response instead of creating a duplicate (findings router);
- **long-task SSE**: ``/assessments/{id}/events`` streams status as
  ``text/event-stream``;
- standard error codes (404 for unknown resources, 422 for invalid payloads).
"""
from __future__ import annotations

import json
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from sqlalchemy.engine import Engine

from ...infrastructure.db.session import Database
from ...infrastructure.db.sqlite import create_sqlite_engine
from ...infrastructure.signing.ed25519 import Ed25519CaseSigner
from .routers import (
    approvals_router,
    assessments_router,
    assets_router,
    audit_router,
    cases_router,
    evidence_router,
    findings_router,
    intel_router,
    jobs_router,
    plans_router,
    projects_router,
    reports_router,
    scopes_router,
    tools_router,
    updates_router,
)


def create_app(engine: Engine | None = None) -> FastAPI:
    """Build an API instance.

    ``engine`` is the SQLAlchemy engine to bind; when omitted a temporary
    SQLite engine is created (for tests / lightweight runs). Resource routers
    are DB-backed via ``app.state.db``. ``app.state.idempotency`` holds the
    per-instance idempotency cache used by the findings router.
    """
    app = FastAPI(title="SecOpent API", version="0.1.0")
    if engine is None:
        engine = create_sqlite_engine(Path(tempfile.mktemp(suffix=".db")))
    app.state.db = Database(engine)
    app.state.idempotency = {}
    # CaseStudio: a server-held Ed25519 signing key. The private key never
    # leaves the server (the frontend can request a signature but never hold the
    # key). Cases themselves persist in the DB (SqlAlchemyCaseRegistry); the
    # cases router builds a CaseService per request around the request session.
    app.state.case_signer = Ed25519CaseSigner.generate()

    # Resource routers (DB-backed, except tools which reads the static catalog).
    app.include_router(projects_router)
    app.include_router(scopes_router)
    app.include_router(assessments_router)
    app.include_router(tools_router)
    app.include_router(findings_router)
    app.include_router(intel_router)
    app.include_router(updates_router)
    app.include_router(audit_router)
    app.include_router(plans_router)
    app.include_router(approvals_router)
    app.include_router(jobs_router)
    app.include_router(assets_router)
    app.include_router(evidence_router)
    app.include_router(reports_router)
    app.include_router(cases_router)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/assessments/{assessment_id}/events")
    def assessment_events(assessment_id: str) -> StreamingResponse:
        """Stream assessment status as server-sent events (long task)."""

        def _stream() -> Iterator[str]:
            for status in ("queued", "running", "completed"):
                event: dict[str, Any] = {
                    "assessment_id": assessment_id,
                    "status": status,
                }
                yield f"data: {json.dumps(event)}\n\n"
                time.sleep(0)

        return StreamingResponse(_stream(), media_type="text/event-stream")

    return app
