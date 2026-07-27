# src/secopent/application/signing_keys.py
"""SigningKeyService: server-held Ed25519 signing keys via SecretStore (decision H).

Multiple named signing keys are supported. Private key material is stored
(encrypted at rest) in the SecretStore and only ever resolved transiently to
produce a signature - it is never returned by any query, so the frontend can
request a signature but never hold a private key (LLM/frontend boundary).

Crypto operations live behind the ``KeyProvider`` protocol (implemented in
infrastructure) so the application layer stays free of ``cryptography``.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from ..domain.common.errors import DomainError
from .secret_store import SecretStore

# Signs payload bytes and returns a transport-safe signature string.
KeySigner = Callable[[bytes], str]


class SigningKeyNotFound(DomainError):
    """Raised when a key_id is unknown (or no keys exist)."""


@runtime_checkable
class KeyProvider(Protocol):
    """Ed25519 key operations, implemented in infrastructure."""

    def generate(self) -> tuple[str, str]:
        """Return (private_material, public_key) as transport-safe strings."""
        ...

    def signer(self, private_material: str) -> KeySigner:
        """Return a signer callable bound to the given private material."""
        ...


@dataclass(frozen=True, slots=True)
class SigningKeyInfo:
    """Public information about a signing key (deliberately no private key)."""

    key_id: str
    name: str
    public_key: str
    created_at: datetime


class SigningKeyService:
    """Manage named signing keys; private material stays in the SecretStore."""

    def __init__(self, secret_store: SecretStore, key_provider: KeyProvider) -> None:
        self._secrets = secret_store
        self._provider = key_provider
        self._keys: dict[str, SigningKeyInfo] = {}

    def create_key(self, name: str, *, now: datetime) -> SigningKeyInfo:
        private_material, public_key = self._provider.generate()
        metadata = self._secrets.register(name, private_material, now=now)
        info = SigningKeyInfo(
            key_id=metadata.secret_ref,
            name=name,
            public_key=public_key,
            created_at=now,
        )
        self._keys[info.key_id] = info
        return info

    def list_keys(self) -> list[SigningKeyInfo]:
        return [self._keys[key_id] for key_id in sorted(self._keys)]

    def get(self, key_id: str) -> SigningKeyInfo:
        info = self._keys.get(key_id)
        if info is None:
            raise SigningKeyNotFound(f"unknown signing key: {key_id}")
        return info

    def default_key_id(self) -> str | None:
        keys = self.list_keys()
        return keys[0].key_id if keys else None

    def signer_for(self, key_id: str | None = None) -> KeySigner:
        """Resolve a signer for ``key_id`` (or the default key).

        The private material is resolved transiently from the SecretStore and
        bound into the returned signer; it is never exposed to the caller.
        """
        target = key_id or self.default_key_id()
        if target is None:
            raise SigningKeyNotFound("no signing keys available")
        self.get(target)
        private_material = self._secrets.resolve(target)
        return self._provider.signer(private_material)
