# src/secopent/interfaces/api/main.py
"""FastAPI OpenAPI surface (§13): command/query separation, idempotency, SSE.

The app is a factory (``create_app``) so tests get an isolated instance.
Resource routers are DB-backed via ``app.state.db``.

Serving modes:
- **Dev**: vite dev server (:5173) proxies ``/api/*`` -> the backend root
  (rewriting the ``/api`` prefix away), so the routers are registered at the
  root here.
- **Production**: when ``SECOPTENT_WEB_DIST`` points at the built frontend, the
  same routers are ALSO mounted under ``/api`` (the frontend calls ``/api/*``
  and there is no proxy to rewrite), and a SPA fallback serves ``index.html``
  for client-side routes.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from ...application.remote_model import RemoteModelGateway
from ...application.secret_store import SecretStore
from ...application.signing_keys import SigningKeyService
from ...domain.common.canonical import utc_now
from ...infrastructure.catalog.default_catalog import build_default_catalog
from ...infrastructure.db.session import Database
from ...infrastructure.db.sqlite import create_sqlite_engine
from ...infrastructure.evidence_store.redaction import RedactionEngine
from ...infrastructure.llm.null_backend import NullModelBackend
from ...infrastructure.llm.remote_openai_backend import RemoteOpenAICompatibleBackend
from ...infrastructure.repositories.sqlalchemy_catalog import (
    SqlAlchemyCatalogRepository,
)
from ...infrastructure.secrets.encrypted_file_backend import EncryptedFileBackend
from ...infrastructure.signing.ed25519 import Ed25519KeyProvider
from .routers import (
    appmodels_router,
    approvals_router,
    assessments_router,
    assets_router,
    audit_router,
    cases_router,
    catalog_router,
    evidence_router,
    findings_router,
    intel_router,
    jobs_router,
    plans_router,
    projects_router,
    reports_router,
    scopes_router,
    signing_keys_router,
    tools_router,
    updates_router,
)


def _register_api(app: FastAPI) -> None:
    """Register all resource routers + health/SSE on a target app."""
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
    app.include_router(appmodels_router)
    app.include_router(signing_keys_router)
    app.include_router(catalog_router)

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


def create_app(engine: Engine | None = None) -> FastAPI:
    """Build an API instance.

    ``engine`` is the SQLAlchemy engine to bind; when omitted a temporary
    SQLite engine is created (for tests / lightweight runs).
    """
    app = FastAPI(title="SecOpent API", version="0.1.0")
    if engine is None:
        engine = create_sqlite_engine(Path(tempfile.mktemp(suffix=".db")))
    app.state.db = Database(engine)
    app.state.idempotency = {}

    # Seed the bundled default TestCatalog (§3.1) so plan generation works out
    # of the box when the store is empty (no operator import required).
    with Session(engine) as seed_session:
        catalog_repo = SqlAlchemyCatalogRepository(seed_session)
        if catalog_repo.latest_catalog() is None:
            catalog_repo.add_catalog(build_default_catalog())
            seed_session.commit()
    # Server-side signing (decision H): Ed25519 private keys are held encrypted
    # at rest in the SecretStore; the frontend can request a signature but never
    # holds a private key. A default key is created at startup.
    signing_keys = SigningKeyService(
        SecretStore(EncryptedFileBackend()), Ed25519KeyProvider()
    )
    signing_keys.create_key("default", now=utc_now())
    app.state.signing_keys = signing_keys

    # Governed LLM gateway (§3.3): MiniMax when MINIMAX_API_KEY is set, else a
    # null backend so LLM-assisted endpoints degrade to their deterministic
    # path. The LLM only ever proposes/drafts - the deterministic layer decides.
    if os.environ.get("MINIMAX_API_KEY"):
        llm_backend = RemoteOpenAICompatibleBackend(
            endpoint="https://api.minimax.chat/v1",
            api_key_env="MINIMAX_API_KEY",
            model="abab6.5s-chat",
        )
    else:
        llm_backend = NullModelBackend()
    app.state.model_gateway = RemoteModelGateway(
        local_backend=llm_backend, redactor=RedactionEngine()
    )

    # API at the root (dev: the vite proxy rewrites /api/* -> root).
    _register_api(app)

    # The same API under /api (production: the frontend calls /api/* directly,
    # no proxy rewrite). The sub-app shares the main app's state objects.
    api = FastAPI()
    api.state.db = app.state.db
    api.state.idempotency = app.state.idempotency
    api.state.signing_keys = app.state.signing_keys
    _register_api(api)
    app.mount("/api", api)

    # Production static serving (W11): serve the built frontend's hashed assets
    # and fall back to index.html for client-side routing. Registered AFTER the
    # /api mount so API routes win; only active when SECOPTENT_WEB_DIST is set.
    web_dist_env = os.environ.get("SECOPTENT_WEB_DIST", "")
    if web_dist_env:
        web_dist = Path(web_dist_env)
        if web_dist.exists():
            assets_dir = web_dist / "assets"
            if assets_dir.exists():
                app.mount(
                    "/assets", StaticFiles(directory=assets_dir), name="web-assets"
                )

            @app.get("/{full_path:path}", include_in_schema=False)
            def spa_fallback(full_path: str) -> FileResponse:
                return FileResponse(web_dist / "index.html")

    return app
