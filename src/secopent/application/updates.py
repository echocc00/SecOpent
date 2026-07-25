"""src/secopent/application/updates.py

UpdateManager (M1 Task 6) - orchestrates the Update Bundle pipeline
described in §10.3 / §10.4:

    download -> stage -> signature verify -> schema/compatibility check
    -> preview diff -> atomic activate (pointer swap) -> retain old snapshot
    -> audit

Design notes
------------
* **Framework-free**: this module imports only stdlib + ``secopent.domain``.
  Ed25519 verification is abstracted behind the ``SignatureVerifier``
  Protocol (``application/ports/repositories.py``); the concrete
  ``cryptography``-backed implementation lives in
  ``infrastructure/signing/ed25519.py``. The architecture-boundary test
  forbids ``cryptography`` in the application layer, so the dependency
  arrow is enforced by import graph.
* **Atomic activation**: delegated to ``BundleRepository.activate()``,
  which performs the single-row pointer swap on
  ``CoreBundleActivation`` (M1 Task 4 singleton=1 pattern). If
  activation raises, ``UpdateManager`` re-points to the previous
  active bundle id (defensive rollback) and re-raises.
* **Old snapshot retained**: ``BundleRepository.stage()`` never deletes;
  ``activate()`` only updates the pointer. ``rollback()`` therefore can
  restore the previous active id from ``get_previous_bundle_id()``.
* **Audit**: every sync (synced/activated/rejected) and rollback emits an
  ``AuditEvent`` through the M0 ``AuditService`` hash chain.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..domain.audit.models import AuditEvent
from ..domain.common.errors import DomainValidationError
from ..domain.updates.models import UpdateBundle
from .audit import AuditService
from .ports.repositories import (
    BundleFetcher,
    BundleRepository,
    SignatureVerifier,
)


@dataclass(frozen=True, slots=True)
class SyncResult:
    """Outcome of a successful ``UpdateManager.sync()`` call.

    Exposed to callers (UI / API) so they can show "what just landed"
    without re-querying the staging store. ``digest`` is the canonical
    SHA-256 of the activated bundle.
    """

    bundle_id: str
    version: str
    digest: str
    previous_bundle_id: str | None


class UpdateManager:
    """Orchestrates Update Bundle sync, activation, and rollback.

    The manager is stateless between calls: all persistent state lives
    in the injected ``BundleRepository`` (staging rows + activation
    pointer) and the ``AuditService`` (hash-chained audit log).
    """

    def __init__(
        self,
        *,
        bundle_repository: BundleRepository,
        audit_service: AuditService,
        signature_verifier: SignatureVerifier,
        fetcher: BundleFetcher,
        expected_schema_version: str,
        public_key: bytes,
    ) -> None:
        self._repo = bundle_repository
        self._audit = audit_service
        self._verifier = signature_verifier
        self._fetcher = fetcher
        self._expected_schema = expected_schema_version
        self._public_key = public_key

    # --- public API --------------------------------------------------------

    def sync(self, *, source: str, bundle: UpdateBundle | None = None) -> SyncResult:
        """Download (or accept an injected ``bundle``), stage, verify, and
        atomically activate an Update Bundle.

        ``bundle`` is optional so tests can inject a pre-parsed bundle
        without exercising the fetcher; production callers leave it as
        ``None`` and the manager invokes ``fetcher.fetch(source)``.

        Raises ``DomainValidationError`` on signature or schema failure.
        Raises whatever the repo raises on activation failure (after
        rolling back to the previous active bundle).
        """
        signature: bytes
        if bundle is None:
            bundle, signature = self._fetch(source)
        else:
            # When a caller injects a bundle directly, pull the signature
            # from the fetcher so the staging row still records it.
            _, signature = self._fetcher.fetch(source)

        previous_active = self._repo.get_active_bundle_id()
        # Stage first; staging never affects the active pointer.
        self._repo.stage(bundle, signature)

        # 1. Signature verification (Ed25519 via SignatureVerifier port).
        if not self._verifier.verify(bundle, signature, self._public_key):
            self._audit.record(
                actor="update-manager",
                action="update.rejected",
                resource_type="update_bundle",
                resource_id=bundle.bundle_id,
                payload={"reason": "signature_invalid", "version": bundle.version},
            )
            raise DomainValidationError(
                f"signature verification failed for bundle {bundle.bundle_id}"
            )

        # 2. Schema compatibility check.
        if bundle.schema_version != self._expected_schema:
            self._audit.record(
                actor="update-manager",
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

        # 3. Preview diff (best-effort; emitted in audit payload).
        diff_summary = _preview_diff(self._repo, previous_active, bundle)

        # 4. Audit the staged+verified sync.
        self._audit.record(
            actor="update-manager",
            action="update.synced",
            resource_type="update_bundle",
            resource_id=bundle.bundle_id,
            payload={
                "version": bundle.version,
                "schema_version": bundle.schema_version,
                "source": source,
                "digest": bundle.digest,
                "diff": diff_summary,
            },
        )

        # 5. Atomic activation. On failure, restore previous and re-raise.
        try:
            self._repo.activate(bundle.bundle_id)
        except Exception as exc:
            # Defensive rollback: only restore if previous existed AND the
            # repo didn't already move the pointer (idempotent guard).
            if (
                previous_active is not None
                and self._repo.get_active_bundle_id() != previous_active
            ):
                self._repo.activate(previous_active)
            self._audit.record(
                actor="update-manager",
                action="update.rejected",
                resource_type="update_bundle",
                resource_id=bundle.bundle_id,
                payload={"reason": "activation_failed", "error": str(exc)},
            )
            raise

        # 6. Audit successful activation.
        self._audit.record(
            actor="update-manager",
            action="update.activated",
            resource_type="update_bundle",
            resource_id=bundle.bundle_id,
            payload={
                "version": bundle.version,
                "previous_bundle_id": previous_active,
                "digest": bundle.digest,
            },
        )

        return SyncResult(
            bundle_id=bundle.bundle_id,
            version=bundle.version,
            digest=bundle.digest,
            previous_bundle_id=previous_active,
        )

    def rollback(self) -> str:
        """Restore the previously active bundle and audit the action.

        Returns the now-active bundle id. Raises ``RuntimeError`` if no
        previous bundle exists to roll back to.
        """
        restored = self._repo.rollback_to_previous()
        if restored is None:
            raise RuntimeError("rollback produced no active bundle")
        self._audit.record(
            actor="update-manager",
            action="update.rolled_back",
            resource_type="update_bundle",
            resource_id=restored,
            payload={"restored_bundle_id": restored},
        )
        return restored

    # --- internals ---------------------------------------------------------

    def _fetch(self, source: str) -> tuple[UpdateBundle, bytes]:
        """Download raw bytes via the fetcher port and parse into a bundle.

        The fetcher returns ``(bundle_bytes, signature_bytes)``. The
        concrete parser is intentionally minimal in this layer: it
        expects the bundle bytes to be a UTF-8 JSON document with the
        manifest + payload fields. The detached signature is returned
        alongside the parsed bundle so it can be staged and verified
        without being embedded in the bundle's digestable payload.
        Real tar.zst unpacking lives in infrastructure.
        """
        import json

        bundle_bytes, signature = self._fetcher.fetch(source)
        try:
            doc = json.loads(bundle_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DomainValidationError(f"bundle bytes are not valid JSON: {exc}") from exc
        payload = dict(doc.get("payload", {}))
        bundle = UpdateBundle.create(
            bundle_id=doc["bundle_id"],
            version=doc["version"],
            schema_version=doc["schema_version"],
            payload=payload,
        )
        return bundle, signature


def _preview_diff(
    repo: BundleRepository,
    previous_active_id: str | None,
    new_bundle: UpdateBundle,
) -> dict[str, object]:
    """Best-effort diff summary between the previously active bundle and
    the new one. Returns a small dict suitable for the audit payload.

    Kept intentionally simple: counts top-level payload keys added /
    removed / changed. Production can swap in a richer diff later; the
    audit schema stays forward-compatible because we only emit a dict.
    """
    if previous_active_id is None:
        return {"added": list(new_bundle.payload.keys()), "removed": [], "changed": []}
    previous = repo.get_staged(previous_active_id)
    if previous is None:
        return {"added": [], "removed": [], "changed": [], "note": "previous not found"}
    prev_payload = getattr(previous, "payload", {}) or {}
    prev_keys = set(prev_payload.keys())
    new_keys = set(new_bundle.payload.keys())
    added = sorted(new_keys - prev_keys)
    removed = sorted(prev_keys - new_keys)
    changed = sorted(k for k in (prev_keys & new_keys) if prev_payload[k] != new_bundle.payload[k])
    return {"added": added, "removed": removed, "changed": changed}


# Re-export for type-checker friendliness.
__all__ = ["SyncResult", "UpdateManager", "AuditEvent"]
