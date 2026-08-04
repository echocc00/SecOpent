# src/secopent/application/secret_store.py
"""SecretStore: reference-only secrets, transient resolution, audited (§12).

Tasks use a ``secret_ref``; the plaintext is never persisted in the domain, the
database, prompts, logs, evidence, or reports. ``resolve`` returns the value
transiently for injection at execution time and audits the ACCESS by reference
only (the value is never written to the audit payload). ``revoke`` deletes the
secret when the task completes. The storage backend is injected (encrypted file
/ keyring / KMS).
"""
from __future__ import annotations

import json
from datetime import datetime

from ..domain.common.canonical import canonical_digest
from ..domain.common.errors import DomainError
from ..domain.secrets.models import SecretMetadata
from .audit import AuditService
from .ports.secrets import SecretBackend


class SecretNotFound(DomainError):
    """Raised when resolving/revoking an unknown secret_ref."""


def _meta_ref(secret_ref: str) -> str:
    """Backend key under which a secret's metadata is persisted."""
    return f"meta:{secret_ref}"


def _metadata_to_json(md: SecretMetadata) -> str:
    return json.dumps(
        {
            "secret_ref": md.secret_ref,
            "name": md.name,
            "created_at": md.created_at.isoformat(),
        }
    )


def _metadata_from_json(payload: str) -> SecretMetadata:
    d = json.loads(payload)
    return SecretMetadata(
        secret_ref=d["secret_ref"],
        name=d["name"],
        created_at=datetime.fromisoformat(d["created_at"]),
    )


class SecretStore:
    """Manage secrets by reference; never expose the value in metadata/audit."""

    def __init__(self, backend: SecretBackend, audit: AuditService | None = None) -> None:
        self._backend = backend
        self._audit = audit
        # In-memory cache of metadata; the source of truth is the backend
        # (W2-C T2) so metadata survives restart alongside the secret value.
        self._metadata: dict[str, SecretMetadata] = {}

    def register(self, name: str, value: str, *, now: datetime) -> SecretMetadata:
        """Store a secret and return its reference-only metadata."""
        digest = canonical_digest({"name": name, "created_at": now})
        secret_ref = "secret:" + digest.removeprefix("sha256:")[:16]
        self._backend.put(secret_ref, value)
        metadata = SecretMetadata(secret_ref=secret_ref, name=name, created_at=now)
        self._backend.put(_meta_ref(secret_ref), _metadata_to_json(metadata))
        self._metadata[secret_ref] = metadata
        self._record("secret.registered", secret_ref, {"name": name})
        return metadata

    def resolve(self, secret_ref: str) -> str:
        """Return the secret value transiently; audit the access by ref only."""
        value = self._backend.get(secret_ref)
        if value is None:
            raise SecretNotFound(f"unknown secret_ref: {secret_ref}")
        # Audit records the reference, never the value.
        self._record("secret.resolved", secret_ref, {})
        return value

    def revoke(self, secret_ref: str) -> None:
        """Delete the secret (call when the task completes)."""
        if self._backend.get(secret_ref) is None:
            raise SecretNotFound(f"unknown secret_ref: {secret_ref}")
        self._backend.delete(secret_ref)
        self._backend.delete(_meta_ref(secret_ref))
        self._metadata.pop(secret_ref, None)
        self._record("secret.revoked", secret_ref, {})

    def metadata(self, secret_ref: str) -> SecretMetadata | None:
        """Return metadata, loading from the backend on miss (survives restart)."""
        cached = self._metadata.get(secret_ref)
        if cached is not None:
            return cached
        payload = self._backend.get(_meta_ref(secret_ref))
        if payload is None:
            return None
        md = _metadata_from_json(payload)
        self._metadata[secret_ref] = md
        return md

    def _record(self, action: str, secret_ref: str, extra: dict[str, object]) -> None:
        if self._audit is None:
            return
        self._audit.record(
            actor="secret_store",
            action=action,
            resource_type="secret",
            resource_id=secret_ref,
            payload=extra,  # never includes the secret value
        )
