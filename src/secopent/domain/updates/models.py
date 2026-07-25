"""src/secopent/domain/updates/models.py

Domain entity for an Update Bundle (§10.4).

An ``UpdateBundle`` is the in-memory representation of a downloaded
``bundle.tar.zst`` once it has been parsed: a manifest (version, schema
version) plus the bundle payload (catalog/intel/cases/tools/models/curation).
The bundle's ``digest`` is a canonical SHA-256 over (bundle_id, version,
schema_version, payload) so the signature verifier and audit log can
reason about a stable identifier.

This module lives in the domain layer: it MUST NOT import frameworks
(``cryptography``, ``sqlalchemy``, ``httpx``). Signature verification is
abstracted behind an application-layer Protocol port
(``SignatureVerifier``) and implemented in infrastructure.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..common.canonical import canonical_digest
from ..common.errors import DomainValidationError


@dataclass(frozen=True, slots=True)
class UpdateBundle:
    """Immutable parsed Update Bundle ready for staging/activation."""

    bundle_id: str
    version: str
    schema_version: str
    payload: dict[str, object]
    digest: str

    @classmethod
    def create(
        cls,
        *,
        bundle_id: str,
        version: str,
        schema_version: str,
        payload: dict[str, object],
    ) -> UpdateBundle:
        if not bundle_id or not version or not schema_version:
            raise DomainValidationError("bundle_id, version, schema_version must not be empty")
        if not isinstance(payload, dict):
            raise DomainValidationError("payload must be a dict")
        digest = canonical_digest(
            {
                "bundle_id": bundle_id,
                "version": version,
                "schema_version": schema_version,
                "payload": payload,
            }
        )
        return cls(
            bundle_id=bundle_id,
            version=version,
            schema_version=schema_version,
            payload=payload,
            digest=digest,
        )
