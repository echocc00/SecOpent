# src/secopent/application/ports/secrets.py
"""Application-layer port for secret storage (W2-C T2).

The concrete backends (EncryptedFileBackend, PersistentEncryptedFileBackend,
future keyring/KMS) live in infrastructure. This Protocol lets SecretStore
depend on the capability without crossing the architecture boundary.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class SecretBackend(Protocol):
    """Stores secret values (encrypted at rest in real backends)."""

    def put(self, secret_ref: str, value: str) -> None: ...

    def get(self, secret_ref: str) -> str | None: ...

    def delete(self, secret_ref: str) -> None: ...
