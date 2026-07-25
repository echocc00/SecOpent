"""src/secopent/infrastructure/signing/ed25519.py

Ed25519 ``SignatureVerifier`` implementation.

Lives in infrastructure (not application) because the architecture
boundary test forbids ``cryptography`` in the application layer. The
application depends on the ``SignatureVerifier`` Protocol; the
composition root wires this concrete implementation in.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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


__all__ = ["Ed25519SignatureVerifier"]
