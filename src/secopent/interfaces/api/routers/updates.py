# src/secopent/interfaces/api/routers/updates.py
"""Updates resource router (Phase A P1, W1; P3 §3.4): knowledge bundle state.

Surface over ``SqlAlchemyUpdateRepository`` + the knowledge-health monitor:
- ``GET /updates/active`` - the currently active bundle id + record;
- ``GET /updates/bundles/{bundle_id}`` - one staged bundle;
- ``GET /updates/health`` - the §7.3 detectors with REAL checkers (P3 §3.4):
  OSV reachability (HTTP probe), git freshness (local clone), curation lag
  (nuclei tags vs TestCatalog), and bundle signature state;
- ``POST /updates/publish`` - sign + activate a real intel bundle with a
  server-held §3.8 Ed25519 key (human-only; LLM boundary).
"""
from __future__ import annotations

import base64
import os
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from ....application.audit import AuditService
from ....application.bundle_sync import BundleSyncService
from ....application.health import KnowledgeHealthMonitor
from ....application.intel_bundle import IntelBundlePublisher
from ....application.signing_keys import SigningKeyNotFound
from ....domain.common.canonical import canonical_digest, utc_now
from ....domain.common.errors import DomainValidationError
from ....infrastructure.health_checkers import (
    BundledNucleiTagProvider,
    CurationLagChecker,
    GitFreshnessChecker,
    LocalNucleiTagProvider,
    NucleiTagProvider,
    OsvReachabilityChecker,
    SignatureChecker,
)
from ....infrastructure.repositories.sqlalchemy_catalog import (
    SqlAlchemyCatalogRepository,
)
from ....infrastructure.repositories.sqlalchemy_core import SqlAlchemyAuditRepository
from ....infrastructure.repositories.sqlalchemy_intel import (
    SqlAlchemyIntelRepository,
    SqlAlchemyUpdateRepository,
)
from ....infrastructure.signing.ed25519 import Ed25519SignatureVerifier
from ....infrastructure.updates.github_bundle_fetcher import (
    BundleFetchError,
    BundleRevokedError,
    GithubBundleFetcher,
)
from ....integrations.adapters import nuclei
from ..deps import DbSession
from ..schemas import (
    ActiveBundleOut,
    ActorRoleBody,
    HealthAlertOut,
    HealthReportOut,
    SyncBundleBody,
    SyncResultOut,
    UpdateBundleOut,
)

router = APIRouter(prefix="/updates", tags=["updates"])

# Local nuclei-templates clone path (optional). When unset, git freshness
# reports stale and the curation checker falls back to a bundled tag baseline.
_NUCLEI_TEMPLATES_ENV = "SECOPTENT_NUCLEI_TEMPLATES_PATH"


def _repo_paths() -> dict[str, str]:
    path = os.environ.get(_NUCLEI_TEMPLATES_ENV, "")
    return {"nuclei-templates": path} if path else {}


def _tag_provider() -> NucleiTagProvider:
    paths = _repo_paths()
    if paths:
        return LocalNucleiTagProvider(paths)
    return BundledNucleiTagProvider()


def _to_out(row: dict[str, Any]) -> UpdateBundleOut:
    return UpdateBundleOut(
        bundle_id=row["bundle_id"],
        version=row["version"],
        digest=row["digest"],
        staged_at=row.get("staged_at"),
    )


@router.get("/health", response_model=HealthReportOut)
def updates_health(request: Request, session: DbSession) -> HealthReportOut:
    """Run the §7.3 knowledge-health detectors and return active alerts.

    All four detectors are real (P3 §3.4): OSV reachability is an HTTP probe;
    git freshness reads a local nuclei-templates clone (stale when absent);
    curation lag counts upstream nuclei tags with no TestCatalog mapping;
    signature state reflects the most recent intel-bundle verification.
    """
    audit = AuditService(SqlAlchemyAuditRepository(session))
    catalog = SqlAlchemyCatalogRepository(session).latest_catalog()
    monitor = KnowledgeHealthMonitor(
        audit_service=audit,
        freshness_checker=GitFreshnessChecker(_repo_paths()),
        curation_checker=CurationLagChecker(
            _tag_provider(), catalog, nuclei.tag_coverage_map()
        ),
        reachability_checker=OsvReachabilityChecker(),
        signature_checker=SignatureChecker(request.app.state.bundle_signature_state),
    )
    report = monitor.check_all()
    return HealthReportOut(
        alerts=[
            HealthAlertOut(kind=a.kind.value, source=a.source, details=a.details)
            for a in report.alerts
        ]
    )


@router.post("/publish", status_code=201, response_model=UpdateBundleOut)
def publish_intel_bundle(
    body: ActorRoleBody, request: Request, session: DbSession
) -> UpdateBundleOut:
    """Sign + activate a real intel update bundle (§3.4-3).

    Builds a payload from live intel/catalog state, signs its digest with a
    server-held Ed25519 key (§3.8), verifies the signature, then stages and
    activates the bundle (audited). Human-only: ``actor_role="agent"`` -> 403
    (publishing is a human admin action; LLM boundary).
    """
    if body.actor_role != "human":
        raise HTTPException(
            status_code=403,
            detail="agents cannot publish intel bundles (human-only admin action)",
        )

    signing_keys = request.app.state.signing_keys
    key_id = body.key_id or signing_keys.default_key_id()
    if key_id is None:
        raise HTTPException(status_code=404, detail="no signing keys available")
    try:
        signer = signing_keys.signer_for(key_id)
        public_key = signing_keys.get(key_id).public_key
    except SigningKeyNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    intel_repo = SqlAlchemyIntelRepository(session)
    catalog = SqlAlchemyCatalogRepository(session).latest_catalog()
    version = utc_now().isoformat()
    payload: dict[str, object] = {
        "kind": "intel",
        "vulnerability_count": intel_repo.count_vulnerabilities(),
        "catalog_version": catalog.version if catalog is not None else "",
        "catalog_digest": catalog.digest if catalog is not None else "",
    }
    bundle_id = "intel-" + canonical_digest(
        {"version": version, "payload": payload}
    ).removeprefix("sha256:")[:16]

    publisher = IntelBundlePublisher(
        verifier=Ed25519SignatureVerifier(),
        audit_service=AuditService(SqlAlchemyAuditRepository(session)),
        store=SqlAlchemyUpdateRepository(session),
        signature_state=request.app.state.bundle_signature_state,
    )
    publisher.publish(
        bundle_id=bundle_id,
        version=version,
        payload=payload,
        signer=signer,
        public_key=public_key,
    )

    row = SqlAlchemyUpdateRepository(session).get_bundle(bundle_id)
    if row is None:  # defensive: publish stages the bundle in the same txn
        raise HTTPException(status_code=500, detail="bundle publish lost state")
    return _to_out(row)


@router.post("/sync", response_model=SyncResultOut)
def sync_bundle(
    body: SyncBundleBody, request: Request, session: DbSession
) -> SyncResultOut:
    """Fetch, verify, and activate an update bundle from a registry (§⑨).

    Resolves ``body.source`` (e.g. ``github:secopent/bundles:v2026.07``) via the
    ``BundleFetcher`` (GitHub Releases by default; overridable via
    ``app.state.bundle_fetcher`` for tests/mirrors), then runs the full
    ``UpdateManager`` pipeline: stage -> Ed25519 verify -> schema check -> atomic
    activate -> audit. Human-only (``actor_role="agent"`` -> 403). A revoked
    bundle -> 409; an unfetchable bundle -> 502; a bad signature/schema -> 422.
    """
    if body.actor_role != "human":
        raise HTTPException(
            status_code=403,
            detail="agents cannot sync update bundles (human-only admin action)",
        )
    fetcher = getattr(request.app.state, "bundle_fetcher", None) or GithubBundleFetcher()
    signing_keys = request.app.state.signing_keys
    key_id = body.key_id or signing_keys.default_key_id()
    if key_id is None:
        raise HTTPException(status_code=404, detail="no signing keys available")
    try:
        public_key_b64 = signing_keys.get(key_id).public_key
    except SigningKeyNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    manager = BundleSyncService(
        fetcher=fetcher,
        verifier=Ed25519SignatureVerifier(),
        store=SqlAlchemyUpdateRepository(session),
        audit_service=AuditService(SqlAlchemyAuditRepository(session)),
        expected_schema_version=IntelBundlePublisher.DEFAULT_SCHEMA,
        public_key=base64.b64decode(public_key_b64),
    )
    try:
        result = manager.sync(source=body.source)
    except BundleRevokedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except BundleFetchError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except DomainValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return SyncResultOut(
        bundle_id=result.bundle_id,
        version=result.version,
        digest=result.digest,
        previous_bundle_id=result.previous_bundle_id,
    )


@router.get("/active", response_model=ActiveBundleOut)
def get_active_bundle(session: DbSession) -> ActiveBundleOut:
    repo = SqlAlchemyUpdateRepository(session)
    active_id = repo.get_active_bundle_id()
    if active_id is None:
        return ActiveBundleOut(active_bundle_id=None, bundle=None)
    row = repo.get_bundle(active_id)
    return ActiveBundleOut(
        active_bundle_id=active_id,
        bundle=_to_out(row) if row else None,
    )


@router.get("/bundles/{bundle_id}", response_model=UpdateBundleOut)
def get_bundle(bundle_id: str, session: DbSession) -> UpdateBundleOut:
    row = SqlAlchemyUpdateRepository(session).get_bundle(bundle_id)
    if row is None:
        raise HTTPException(status_code=404, detail="bundle not found")
    return _to_out(row)
