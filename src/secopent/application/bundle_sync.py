# src/secopent/application/bundle_sync.py
"""BundleSyncService (T17 / cross-cutting §⑨): fetch -> verify -> activate.

The distribution counterpart to ``IntelBundlePublisher`` (which signs and
activates a LOCALLY built bundle): this service acquires a bundle from a remote
registry via the ``BundleFetcher`` port, verifies its Ed25519 signature and
schema compatibility, then stages and atomically activates it through the
``SyncStore`` port - auditing each outcome on the hash chain. Revocation is
enforced by the fetcher (it raises ``BundleRevokedError`` for a revoked tag).

Framework-free: stdlib + ``secopent.domain`` + application ports/services only
(the architecture-boundary test forbids frameworks in this layer). The concrete
fetcher (``GithubBundleFetcher``), verifier (``Ed25519SignatureVerifier``) and
store (``SqlAlchemyUpdateRepository``) are injected at the composition root.
"""
from __future__ import annotations

import json
from typing import Any, Protocol, runtime_checkable

from ..domain.common.errors import DomainValidationError
from ..domain.updates.models import UpdateBundle
from .audit import AuditService
from .ports.repositories import BundleFetcher, SignatureVerifier
from .updates import SyncResult


@runtime_checkable
class SyncStore(Protocol):
    """Persistence port for a synced bundle (stage + activate + read pointer)."""

    def add_bundle(
        self, bundle_id: str, version: str, digest: str, payload: dict[str, Any]
    ) -> None: ...

    def set_active_bundle(self, bundle_id: str) -> None: ...

    def get_active_bundle_id(self) -> str | None: ...


class BundleSyncService:
    """Fetch, verify, and activate an update bundle from a registry."""

    def __init__(
        self,
        *,
        fetcher: BundleFetcher,
        verifier: SignatureVerifier,
        store: SyncStore,
        audit_service: AuditService,
        expected_schema_version: str,
        public_key: bytes,
    ) -> None:
        self._fetcher = fetcher
        self._verifier = verifier
        self._store = store
        self._audit = audit_service
        self._expected_schema = expected_schema_version
        self._public_key = public_key

    def sync(self, *, source: str) -> SyncResult:
        """Download, verify, stage, and activate the bundle at ``source``.

        Raises ``BundleRevokedError`` (from the fetcher) if the bundle is
        revoked, and ``DomainValidationError`` on a bad signature, schema
        mismatch, or unparseable bundle.
        """
        bundle_bytes, signature = self._fetcher.fetch(source)
        bundle = self._parse(bundle_bytes)
        previous = self._store.get_active_bundle_id()

        if not self._verifier.verify(bundle, signature, self._public_key):
            self._audit.record(
                actor="bundle-sync",
                action="update.rejected",
                resource_type="update_bundle",
                resource_id=bundle.bundle_id,
                payload={
                    "reason": "signature_invalid",
                    "version": bundle.version,
                    "source": source,
                },
            )
            raise DomainValidationError(
                f"signature verification failed for bundle {bundle.bundle_id}"
            )

        if bundle.schema_version != self._expected_schema:
            self._audit.record(
                actor="bundle-sync",
                action="update.rejected",
                resource_type="update_bundle",
                resource_id=bundle.bundle_id,
                payload={
                    "reason": "schema_incompatible",
                    "bundle_schema": bundle.schema_version,
                    "expected_schema": self._expected_schema,
                },
            )
            raise DomainValidationError(
                f"schema version mismatch: bundle={bundle.schema_version} "
                f"expected={self._expected_schema}"
            )

        self._store.add_bundle(
            bundle.bundle_id, bundle.version, bundle.digest, dict(bundle.payload)
        )
        self._store.set_active_bundle(bundle.bundle_id)
        self._audit.record(
            actor="bundle-sync",
            action="update.synced",
            resource_type="update_bundle",
            resource_id=bundle.bundle_id,
            payload={
                "version": bundle.version,
                "schema_version": bundle.schema_version,
                "source": source,
                "digest": bundle.digest,
                "previous_bundle_id": previous,
            },
        )
        return SyncResult(
            bundle_id=bundle.bundle_id,
            version=bundle.version,
            digest=bundle.digest,
            previous_bundle_id=previous,
        )

    @staticmethod
    def _parse(bundle_bytes: bytes) -> UpdateBundle:
        try:
            doc = json.loads(bundle_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DomainValidationError(f"bundle bytes are not valid JSON: {exc}") from exc
        return UpdateBundle.create(
            bundle_id=doc["bundle_id"],
            version=doc["version"],
            schema_version=doc["schema_version"],
            payload=dict(doc.get("payload", {})),
        )


__all__ = ["BundleSyncService", "SyncResult", "SyncStore"]
