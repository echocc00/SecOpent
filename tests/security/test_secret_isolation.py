"""TDD tests for SecretStore isolation (M5 Task 3, §12)."""
from __future__ import annotations

from dataclasses import dataclass, field, fields
from datetime import UTC, datetime

import pytest

from secopent.application.audit import AuditService
from secopent.application.secret_store import SecretNotFound, SecretStore
from secopent.domain.audit.models import GENESIS_HASH, AuditEvent
from secopent.domain.secrets.models import SecretMetadata
from secopent.infrastructure.secrets.encrypted_file_backend import EncryptedFileBackend

_T0 = datetime(2026, 1, 1, tzinfo=UTC)
_PLAINTEXT = "super-secret-api-key-123"


@dataclass
class _MemoryAuditRepo:
    events: list[AuditEvent] = field(default_factory=list)

    def add(self, e: AuditEvent) -> None:
        self.events.append(e)

    def list_events(self) -> list[AuditEvent]:
        return list(self.events)

    def last_hash(self) -> str:
        return self.events[-1].event_hash.removeprefix("sha256:") if self.events else GENESIS_HASH


def _store() -> tuple[SecretStore, EncryptedFileBackend, _MemoryAuditRepo]:
    backend = EncryptedFileBackend()
    repo = _MemoryAuditRepo()
    return SecretStore(backend, AuditService(repo)), backend, repo


def test_register_returns_ref_only_metadata() -> None:
    store, _, _ = _store()
    meta = store.register("api_key", _PLAINTEXT, now=_T0)
    assert isinstance(meta, SecretMetadata)
    assert meta.secret_ref.startswith("secret:")
    # The metadata carries no plaintext value.
    assert "value" not in {f.name for f in fields(SecretMetadata)}


def test_resolve_returns_original_value() -> None:
    store, _, _ = _store()
    meta = store.register("api_key", _PLAINTEXT, now=_T0)
    assert store.resolve(meta.secret_ref) == _PLAINTEXT


def test_secret_encrypted_at_rest() -> None:
    store, backend, _ = _store()
    meta = store.register("api_key", _PLAINTEXT, now=_T0)
    token = backend.encrypted_token(meta.secret_ref)
    assert token is not None
    assert _PLAINTEXT not in token  # not stored in the clear


def test_revoke_then_resolve_fails() -> None:
    store, _, _ = _store()
    meta = store.register("api_key", _PLAINTEXT, now=_T0)
    store.revoke(meta.secret_ref)
    with pytest.raises(SecretNotFound):
        store.resolve(meta.secret_ref)


def test_audit_records_ref_but_never_value() -> None:
    store, _, repo = _store()
    meta = store.register("api_key", _PLAINTEXT, now=_T0)
    store.resolve(meta.secret_ref)
    # No audit payload contains the plaintext secret.
    for event in repo.list_events():
        assert _PLAINTEXT not in str(event.payload)
    # But the reference is recorded.
    assert any(event.resource_id == meta.secret_ref for event in repo.list_events())
