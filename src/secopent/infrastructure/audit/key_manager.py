# src/secopent/infrastructure/audit/key_manager.py
"""Ed25519 audit key management (§12).

The audit signing key is INDEPENDENT of the update-bundle signing key. The
private key is held by the key manager (OS keyring in production; in-memory here
for tests); the public key is exportable so a third party can verify the audit
chain alongside the report.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class AuditKeyManager:
    """Sign and verify audit events with an Ed25519 key pair."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self._private = private_key or Ed25519PrivateKey.generate()

    def sign(self, message: bytes) -> str:
        return self._private.sign(message).hex()

    def verify(self, message: bytes, signature: str) -> bool:
        try:
            self._private.public_key().verify(bytes.fromhex(signature), message)
            return True
        except (InvalidSignature, ValueError):
            return False

    def public_key_bytes(self) -> bytes:
        """Raw public key bytes (export with the report for third-party verify)."""
        return self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @staticmethod
    def verifier_from_public_key(public_key_bytes: bytes) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(public_key_bytes)
