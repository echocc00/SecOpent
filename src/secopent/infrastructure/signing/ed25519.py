"""src/secopent/infrastructure/signing/ed25519.py

Ed25519 ``SignatureVerifier`` implementation.

Lives in infrastructure (not application) because the architecture
boundary test forbids ``cryptography`` in the application layer. The
application depends on the ``SignatureVerifier`` Protocol; the
composition root wires this concrete implementation in.
"""
from __future__ import annotations

import base64
from collections.abc import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ...domain.updates.models import UpdateBundle


class Ed25519SignatureVerifier:
    """Verify an Update Bundle signature using Ed25519.

    Satisfies the application-layer ``SignatureVerifier`` Protocol
    structurally (duck-typed); the protocol is not declared as a base
    class so the infrastructure package stays free of an import arrow
    back into application. The architecture-boundary test only forbids
    ``cryptography`` in application; the protocol indirection keeps
    that import graph honest.

    The signed message is the bundle's canonical digest
    (``bundle.digest``) as UTF-8 bytes - the same value the audit log
    records, so a third party with the public key and the audit trail
    can re-verify any activation without re-reading the bundle payload.
    """

    def verify(self, bundle: UpdateBundle, signature: bytes, public_key: bytes) -> bool:
        if not signature or not public_key:
            return False
        try:
            if public_key.startswith(b"-----BEGIN"):
                pk = serialization.load_pem_public_key(public_key)
            else:
                pk = Ed25519PublicKey.from_public_bytes(public_key)
        except (ValueError, TypeError):
            return False
        if not isinstance(pk, Ed25519PublicKey):
            return False
        message = bundle.digest.encode("utf-8")
        try:
            pk.verify(signature, message)
            return True
        except InvalidSignature:
            return False


__all__ = ["Ed25519SignatureVerifier", "Ed25519CaseSigner", "Ed25519KeyProvider"]


class Ed25519CaseSigner:
    """Sign case/model payloads with a server-held Ed25519 private key.

    Satisfies the application-layer ``CaseSigner`` alias
    (``Callable[[bytes], str]``) via ``__call__``. The private key is held
    server-side and NEVER exposed - only signatures leave this object, which is
    what enforces the LLM/frontend boundary (the frontend can request a
    signature but can never hold the signing key).

    The signature is the raw Ed25519 signature, base64-encoded for transport.
    """

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key

    @classmethod
    def generate(cls) -> Ed25519CaseSigner:
        """Create a signer with a fresh ephemeral key (dev / single-run)."""
        return cls(Ed25519PrivateKey.generate())

    def sign(self, payload: bytes) -> str:
        signature = self._key.sign(payload)
        return base64.b64encode(signature).decode("ascii")

    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte public key (safe to share for verification)."""
        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def __call__(self, payload: bytes) -> str:
        return self.sign(payload)


class Ed25519KeyProvider:
    """``KeyProvider`` implementation using Ed25519 (decision H).

    Satisfies the application-layer ``KeyProvider`` protocol structurally.
    Private keys are serialized as base64 raw 32-byte seeds so they can be
    stored as strings in the SecretStore (encrypted at rest); public keys are
    base64 raw 32-byte keys, safe to expose for verification.
    """

    def generate(self) -> tuple[str, str]:
        key = Ed25519PrivateKey.generate()
        private_bytes = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return (
            base64.b64encode(private_bytes).decode("ascii"),
            base64.b64encode(public_bytes).decode("ascii"),
        )

    def signer(self, private_material: str) -> Callable[[bytes], str]:
        key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_material))

        def sign(payload: bytes) -> str:
            return base64.b64encode(key.sign(payload)).decode("ascii")

        return sign
