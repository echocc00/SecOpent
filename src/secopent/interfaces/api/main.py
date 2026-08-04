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

import os
import threading
import time
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from ...application.audit_chain import AuditChain
from ...application.canary import CanaryTokenManager
from ...application.emergency_stop import EmergencyStop
from ...application.health import BundleSignatureState
from ...application.oracle_service import OracleService
from ...application.prompt_injection import PromptInjectionGuard
from ...application.remote_model import ModelBackend, RemoteModelGateway
from ...application.scope_enforcer import ScopeEnforcer
from ...application.secret_store import SecretStore
from ...application.signing_keys import SigningKeyService
from ...domain.assessments.models import AssessmentStatus
from ...domain.common.canonical import utc_now
from ...domain.verification.registry import default_registry
from ...infrastructure.adapters.real_scan import RealScanRunner
from ...infrastructure.audit.key_manager import AuditKeyManager
from ...infrastructure.catalog.default_catalog import build_default_catalog
from ...infrastructure.db.engine import (
    configured_database_url,
    create_engine_from_url,
)
from ...infrastructure.db.session import Database
from ...infrastructure.db.sqlite import create_sqlite_engine
from ...infrastructure.egress.egress_guard import EgressGuard
from ...infrastructure.egress.nft_scope import NftScopeEnforcer, SocketDnsResolver
from ...infrastructure.evidence_store.redaction import RedactionEngine
from ...infrastructure.llm.null_backend import NullModelBackend
from ...infrastructure.llm.remote_openai_backend import RemoteOpenAICompatibleBackend
from ...infrastructure.logging_setup import configure_logging
from ...infrastructure.observability.context import install_request_context
from ...infrastructure.observability.metrics import render_metrics
from ...infrastructure.observability.tracing import setup_tracing
from ...infrastructure.oracle.verifier_factory import RescanVerifierFactory
from ...infrastructure.permits.permit_signer import PermitSigner, PermitVerifier
from ...infrastructure.repositories.sqlalchemy_catalog import (
    SqlAlchemyCatalogRepository,
)
from ...infrastructure.repositories.sqlalchemy_core import (
    SqlAlchemyAssessmentRepository,
)
from ...infrastructure.safety.emergency_infra import DockerContainerTerminator
from ...infrastructure.safety.permit_revoker import InMemoryPermitRevoker
from ...infrastructure.secrets.encrypted_file_backend import EncryptedFileBackend
from ...infrastructure.secrets.persistent_file_backend import (
    PersistentEncryptedFileBackend,
)
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
from .sse import event_stream

# Assessment statuses that end the SSE stream (no further state changes).
_TERMINAL_ASSESSMENT_STATUSES = frozenset(
    {"completed", "partial", "failed", "cancelled", "rejected"}
)


# Wall-clock budget for draining in-flight assessments on shutdown. systemd's
# TimeoutStopSec=30 leaves a margin for the SIGTERM -> drain -> SIGKILL window.
_SHUTDOWN_DRAIN_SECONDS = 25.0


def _drain_active_executions(app: FastAPI) -> None:
    """SIGTERM/shutdown grace: stop execution containers, wait for in-flight runs.

    Reuses the emergency-stop container terminator so an in-flight adapter step
    fails fast and the executor's except-branch records FAILED (rather than the
    thread being SIGKILLed mid-step, which would leave a RUNNING assessment for
    startup recovery). Best-effort: any thread still alive after the budget is
    force-killed by systemd SIGKILL; startup recovery transitions the leftover
    RUNNING status to FAILED on next boot.
    """
    threads: list[threading.Thread] = []
    with app.state.active_executions_lock:
        threads = list(app.state.active_executions)
    if not threads:
        return
    try:
        from ...infrastructure.safety.emergency_infra import (
            DockerContainerTerminator,
        )

        DockerContainerTerminator().terminate_active()
    except Exception:  # noqa: BLE001 - shutdown must not fail on docker being down
        pass
    deadline = time.monotonic() + _SHUTDOWN_DRAIN_SECONDS
    for thread in threads:
        remaining = max(0.0, deadline - time.monotonic())
        thread.join(timeout=remaining)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """App lifespan: drain in-flight assessments on shutdown (SIGTERM grace).

    The execution-tracking state is initialized in ``create_app`` (not here) so
    it is present even when the app is constructed without a running server
    (e.g. TestClient-less unit tests that still hit the start endpoint).
    """
    yield
    app.state.shutdown_event.set()
    _drain_active_executions(app)


def _build_secret_backend() -> EncryptedFileBackend | PersistentEncryptedFileBackend:
    """Pick the secret backend (W2-C T3: persistent by default).

    ``SECOPTENT_SECRET_BACKEND=memory`` -> in-memory EncryptedFileBackend (tests;
    secrets lost on restart). Otherwise -> PersistentEncryptedFileBackend so
    signed Cases/AppModels stay verifiable across restart:

    - store path: ``SECOPTENT_SECRET_STORE_PATH`` or ``./secrets.json``
    - key:        ``SECOPTENT_SECRET_KEY`` (Fernet key, KMS/operator-injected,
                  never written to disk) else ``SECOPTENT_SECRET_KEY_PATH`` or
                  ``./secret.key`` (auto-generated 0600 on first start)

    Production should inject the key via env (KMS/age-encrypted); the auto-
    generated key file is the dev escrow (back it up independently).
    """
    if os.environ.get("SECOPTENT_SECRET_BACKEND") == "memory":
        return EncryptedFileBackend()
    store_path = Path(os.environ.get("SECOPTENT_SECRET_STORE_PATH", "secrets.json"))
    key_path = Path(os.environ.get("SECOPTENT_SECRET_KEY_PATH", "secret.key"))
    return PersistentEncryptedFileBackend(
        store_path, key_path, env_key="SECOPTENT_SECRET_KEY",
    )


def _signing_key_metadata_path() -> Path | None:
    """Optional signing-key metadata file (public keys, 0600).

    Persisted alongside the SecretStore so signatures stay verifiable after
    restart. None when the persistent backend is not in use (dev/test).
    """
    if not os.environ.get("SECOPTENT_SECRET_STORE_PATH"):
        return None
    meta_env = os.environ.get("SECOPTENT_SIGNING_KEY_METADATA_PATH")
    if meta_env:
        return Path(meta_env)
    return Path(os.environ["SECOPTENT_SECRET_STORE_PATH"]).with_name(
        "signing_keys.json"
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

    @app.get("/metrics", include_in_schema=False)
    def metrics() -> Response:
        """Prometheus metrics (T16) in the text exposition format."""
        return Response(
            content=render_metrics(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/assessments/{assessment_id}/events")
    async def assessment_events(
        assessment_id: str, request: Request
    ) -> StreamingResponse:
        """Stream assessment status as SSE with bounded backpressure (P3 §3.5).

        Polls the assessment's live status each tick, emits only on change
        (signature de-dup), bounds memory via a 64-slot queue (a slow client is
        dropped, never OOM), and stops on client disconnect or a terminal status.
        """
        db: Database = app.state.db

        async def snapshot() -> list[dict[str, Any]]:
            session = db.open_session()
            try:
                assessment = SqlAlchemyAssessmentRepository(session).get(assessment_id)
            finally:
                session.close()
            status = assessment.status.value if assessment is not None else "not_found"
            return [{"assessment_id": assessment_id, "status": status}]

        def stop_when(events: Sequence[dict[str, Any]]) -> bool:
            if not events:
                return False
            status = events[0].get("status")
            return status == "not_found" or status in _TERMINAL_ASSESSMENT_STATUSES

        return StreamingResponse(
            event_stream(
                snapshot,
                is_disconnected=request.is_disconnected,
                stop_when=stop_when,
            ),
            media_type="text/event-stream",
        )


def create_app(engine: Engine | None = None) -> FastAPI:
    """Build an API instance.

    ``engine`` is the SQLAlchemy engine to bind; when omitted a temporary
    SQLite engine is created (for tests / lightweight runs).
    """
    app = FastAPI(title="SecOpent API", version="0.1.0", lifespan=_lifespan)
    # Structured logging (§3.8): JSON when SECOPTENT_LOG_FORMAT=json, with
    # sensitive-field redaction. Idempotent across calls.
    configure_logging(json_format=os.environ.get("SECOPTENT_LOG_FORMAT") == "json")
    if engine is None:
        configured = configured_database_url()
        if configured is not None:
            # SECOPTENT_DB_URL selects the backend (sqlite:/// or postgresql://).
            engine = create_engine_from_url(configured)
        else:
            # Default to a stable on-disk path (NOT mkstemp) so data survives
            # restart when SECOPTENT_DB_URL is unset (NAS/long-lived deployments
            # - the prior mkstemp created a fresh /tmp/tmp*.db each start,
            # silently losing all data). Production should still set
            # SECOPTENT_DB_URL explicitly (see docs/deployment/linux.md); tests
            # isolate via SECOPTENT_DB_URL in conftest.
            db_path = Path.cwd() / "secopent.db"
            engine = create_sqlite_engine(db_path)
    app.state.db = Database(engine)
    app.state.idempotency = {}
    # Execution-tracking state for graceful shutdown (v0.1.5): in-flight
    # assessment threads register here so SIGTERM can drain them (terminate
    # execution containers + join) rather than being SIGKILLed mid-step.
    app.state.shutdown_event = threading.Event()
    app.state.active_executions = set()
    app.state.active_executions_lock = threading.Lock()

    # Startup recovery: any assessment left in RUNNING/QUEUED from a prior
    # process (crash, restart, deploy) is transitioned to FAILED so it does not
    # spin forever in the UI. The operator can re-start it explicitly.
    with Session(engine) as recovery_session:
        recovery_repo = SqlAlchemyAssessmentRepository(recovery_session)
        stale_statuses = {AssessmentStatus.RUNNING, AssessmentStatus.QUEUED}
        for assessment in recovery_repo.list_all():
            if assessment.status in stale_statuses:
                recovery_repo.add(
                    replace(assessment, status=AssessmentStatus.FAILED)
                )
        recovery_session.commit()

    # Seed the bundled default TestCatalog (§3.1) so plan generation works out
    # of the box when the store is empty (no operator import required).
    with Session(engine) as seed_session:
        catalog_repo = SqlAlchemyCatalogRepository(seed_session)
        if catalog_repo.latest_catalog() is None:
            catalog_repo.add_catalog(build_default_catalog())
            seed_session.commit()
    # Server-side signing (decision H): Ed25519 private keys are held encrypted
    # at rest in the SecretStore; the frontend can request a signature but never
    # holds a private key. A default key is created at startup (idempotent across
    # restarts when the persistent backend is configured, so signed Cases stay
    # verifiable).
    signing_keys = SigningKeyService(
        SecretStore(_build_secret_backend()),
        Ed25519KeyProvider(),
        key_metadata_path=_signing_key_metadata_path(),
    )
    signing_keys.ensure_default_key("default", now=utc_now())
    app.state.signing_keys = signing_keys
    # Shared state for the §7.3 signature detector (P3 §3.4): the intel bundle
    # publisher records each real verification here; /updates/health reads it.
    app.state.bundle_signature_state = BundleSignatureState()

    # Security components (W2-A T6): signed permit chain + emergency stop +
    # signed audit chain + scope enforcement. One shared instance each so the
    # /stop route, the background executor, and the /api sub-app all see the
    # same kill-switch flag, permit registry, and signed audit chain.
    permit_signer = PermitSigner()
    permit_registry = InMemoryPermitRevoker()
    audit_chain = AuditChain(AuditKeyManager())
    app.state.permit_signer = permit_signer
    app.state.permit_verifier = PermitVerifier(permit_signer.public_key_bytes())
    app.state.permit_registry = permit_registry
    app.state.audit_chain = audit_chain
    app.state.scope_enforcer = ScopeEnforcer(SocketDnsResolver())
    app.state.emergency_stop = EmergencyStop(
        permit_revoker=permit_registry,
        container_terminator=DockerContainerTerminator(),
        audit=audit_chain,
    )
    # Egress guard (app-layer pre-check; nftables kernel enforcement in W2-B)
    # and prompt-injection guard (validates agent actions on the proposal path).
    app.state.egress_guard = EgressGuard(SocketDnsResolver())
    app.state.prompt_injection_guard = PromptInjectionGuard()
    # Kernel-level egress (W2-B): pushes the scope's resolved targets into the
    # nftables allow/block sets so egress is enforced at the packet level. The
    # execution path calls apply_scope/revoke around dispatch; on non-Linux dev
    # hosts apply_scope is best-effort (no nft binary -> audited + skipped).
    app.state.nft_scope_enforcer = NftScopeEnforcer(
        SocketDnsResolver(),
        guard=app.state.egress_guard,
        audit=audit_chain,
    )

    # Oracle (W3-A): canary singleton auditing to the shared signed chain + a
    # shared RealScanRunner for N/N rescan reproduction. OracleService is
    # session-independent; per-thread finding/confirmed repos are passed by the
    # assessments router from the background session. The oracle runs after
    # correlation in execute_assessment (best-effort: failures do not block the
    # assessment - findings stay unconfirmed but persisted).
    canary = CanaryTokenManager(audit_chain)
    try:
        scan_timeout = int(os.environ.get("SECOPTENT_SCAN_TIMEOUT", "1800"))
    except ValueError:
        scan_timeout = 1800
    oracle_scan_runner = RealScanRunner(default_timeout=scan_timeout)
    template_host_dir = (
        os.environ.get("SECOPTENT_NUCLEI_TEMPLATE_DIR", "").strip() or None
    )
    verifier_factory = RescanVerifierFactory(
        oracle_scan_runner, template_host_dir, canary
    )
    app.state.canary = canary
    app.state.oracle = OracleService(
        registry=default_registry(),
        canary=canary,
        verifier_factory=verifier_factory,
    )

    # Governed LLM gateway (§3.3): MiniMax when MINIMAX_API_KEY is set, else a
    # null backend so LLM-assisted endpoints degrade to their deterministic
    # path. The LLM only ever proposes/drafts - the deterministic layer decides.
    llm_backend: ModelBackend
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
    api.state.permit_signer = app.state.permit_signer
    api.state.permit_verifier = app.state.permit_verifier
    api.state.permit_registry = app.state.permit_registry
    api.state.audit_chain = app.state.audit_chain
    api.state.scope_enforcer = app.state.scope_enforcer
    api.state.emergency_stop = app.state.emergency_stop
    api.state.egress_guard = app.state.egress_guard
    api.state.prompt_injection_guard = app.state.prompt_injection_guard
    api.state.nft_scope_enforcer = app.state.nft_scope_enforcer
    api.state.canary = app.state.canary
    api.state.oracle = app.state.oracle
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

    # Observability (T16): bind request_id/tenant into structured logs for every
    # request, and enable best-effort OpenTelemetry tracing. /metrics lives in
    # _register_api so it is served at both the root and the /api sub-app.
    install_request_context(app)
    setup_tracing(app)

    return app
