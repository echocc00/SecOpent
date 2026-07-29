# src/secopent/application/intel_bundle.py
"""IntelBundlePublisher (P3 §3.4-3): sign + activate a real intel update bundle.

Builds an ``UpdateBundle`` from intel-store state, signs its stable digest with
a server-held §3.8 Ed25519 key, verifies the signature through the
``SignatureVerifier`` port (real ``cryptography`` lives in infrastructure), then
stages + activates the bundle and audits the action. The most recent
verification result is recorded on a shared ``BundleSignatureState`` so the
§7.3 signature detector reports real cumulative state.

Framework-free: stdlib + ``secopent.domain`` + application ports/services only
(the architecture-boundary test forbids frameworks in this layer). The concrete
repository (``SqlAlchemyUpdateRepository``) and verifier
(``Ed25519SignatureVerifier``) are injected at the composition root and satisfy
the ``BundleStore`` / ``SignatureVerifier`` protocols structurally.
"""
from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from ..domain.common.errors import DomainValidationError
from ..domain.updates.models import UpdateBundle
from .audit import AuditService
from .health import BundleSignatureState
from .ports.repositories import SignatureVerifier

# Signs payload bytes and returns a transport-safe (base64) signature string -
# the same shape ``SigningKeyService.signer_for`` returns.
Signer = Callable[[bytes], str]


class BundleStore(Protocol):
    """Persistence port for publishing a bundle (stage + activate)."""

    def add_bundle(
        self, bundle_id: str, version: str, digest: str, payload: dict[str, Any]
    ) -> None: ...

    def set_active_bundle(self, bundle_id: str) -> None: ...


@dataclass(frozen=True, slots=True)
class PublishResult:
    """Outcome of a successful publish (exposed to the API caller)."""

    bundle_id: str
    version: str
    digest: str
    signature_valid: bool


class IntelBundlePublisher:
    """Sign, verify, stage, and activate an intel update bundle."""

    DEFAULT_SCHEMA = "secopent-intel/v1"

    def __init__(
        self,
        *,
        verifier: SignatureVerifier,
        audit_service: AuditService,
        store: BundleStore,
        signature_state: BundleSignatureState | None = None,
        schema_version: str = DEFAULT_SCHEMA,
    ) -> None:
        self._verifier = verifier
        self._audit = audit_service
        self._store = store
        self._signature_state = signature_state
        self._schema = schema_version

    def publish(
        self,
        *,
        bundle_id: str,
        version: str,
        payload: dict[str, object],
        signer: Signer,
        public_key: str,
    ) -> PublishResult:
        """Build, sign, verify, stage, and activate one intel bundle.

        ``signer`` signs ``bundle.digest`` (base64 signature); ``public_key`` is
        the base64 raw Ed25519 public key used to verify. On verification
        failure the result is recorded and ``DomainValidationError`` is raised
        (nothing is activated). On success the bundle is staged, set active, and
        audited (``update.published``).
        """
        bundle = UpdateBundle.create(
            bundle_id=bundle_id,
            version=version,
            schema_version=self._schema,
            payload=payload,
        )
        signature = base64.b64decode(signer(bundle.digest.encode("utf-8")))
        public_key_bytes = base64.b64decode(public_key)
        valid = self._verifier.verify(bundle, signature, public_key_bytes)

        if self._signature_state is not None:
            self._signature_state.record(bundle.bundle_id, valid=valid)

        if not valid:
            self._audit.record(
                actor="intel-publisher",
                action="update.rejected",
                resource_type="update_bundle",
                resource_id=bundle.bundle_id,
                payload={"reason": "signature_invalid", "version": bundle.version},
            )
            raise DomainValidationError(
                f"intel bundle signature verification failed: {bundle.bundle_id}"
            )

        self._store.add_bundle(
            bundle.bundle_id, bundle.version, bundle.digest, dict(bundle.payload)
        )
        self._store.set_active_bundle(bundle.bundle_id)
        self._audit.record(
            actor="intel-publisher",
            action="update.published",
            resource_type="update_bundle",
            resource_id=bundle.bundle_id,
            payload={
                "version": bundle.version,
                "schema_version": bundle.schema_version,
                "digest": bundle.digest,
            },
        )
        return PublishResult(
            bundle_id=bundle.bundle_id,
            version=bundle.version,
            digest=bundle.digest,
            signature_valid=valid,
        )


__all__ = ["BundleStore", "IntelBundlePublisher", "PublishResult", "Signer"]
