# src/secopent/infrastructure/secrets/encrypted_file_backend.py
"""Encrypted-at-rest secret backend (Fernet) (§12).

Stores each secret value encrypted with a Fernet symmetric key, so the plaintext
is never at rest in the clear. Keyring/KMS backends implement the same
``SecretBackend`` protocol; this one needs no external service and is testable.
"""
from __future__ import annotations

from cryptography.fernet import Fernet


class EncryptedFileBackend:
    """In-memory encrypted secret store (Fernet); values encrypted at rest."""

    def __init__(self, key: bytes | None = None) -> None:
        self._fernet = Fernet(key or Fernet.generate_key())
        self._store: dict[str, str] = {}  # secret_ref -> encrypted token

    def put(self, secret_ref: str, value: str) -> None:
        self._store[secret_ref] = self._fernet.encrypt(value.encode("utf-8")).decode()

    def get(self, secret_ref: str) -> str | None:
        token = self._store.get(secret_ref)
        if token is None:
            return None
        return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")

    def delete(self, secret_ref: str) -> None:
        self._store.pop(secret_ref, None)

    def encrypted_token(self, secret_ref: str) -> str | None:
        """Expose the stored (encrypted) token - for verifying encryption at rest."""
        return self._store.get(secret_ref)
