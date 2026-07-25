# src/secopent/infrastructure/permits/permit_signer.py
"""Ed25519 issue/verify for ExecutionPermits (§12 signed short-lived permits).

Lives in infrastructure because the architecture boundary forbids
``cryptography`` in the application layer. ``PermitSigner`` holds the private
key and issues signed permits; ``PermitVerifier`` holds only the public key
(exports separately so a third party can verify) and enforces signature +
expiry + nonce-replay + worker-binding.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from secopent.domain.permits.models import (
    ExecutionPermit,
    PermitExpired,
    PermitReplayed,
    PermitSignatureInvalid,
    PermitWorkerMismatch,
)


class PermitSigner:
    """Issue Ed25519-signed execution permits."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self._private = private_key or Ed25519PrivateKey.generate()

    def issue(self, permit: ExecutionPermit) -> ExecutionPermit:
        """Sign the permit's content and return a copy carrying the signature."""
        signature = self._private.sign(permit.signing_payload())
        return replace(permit, signature=signature.hex())

    def public_key_bytes(self) -> bytes:
        """Raw public key bytes (exportable for third-party verification)."""
        return self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


class PermitVerifier:
    """Verify permits with a public key: signature + expiry + replay + worker."""

    def __init__(self, public_key_bytes: bytes) -> None:
        self._public = Ed25519PublicKey.from_public_bytes(public_key_bytes)

    def verify(
        self,
        permit: ExecutionPermit,
        *,
        now: datetime,
        used_nonces: set[str] | frozenset[str],
        expected_worker: str | None = None,
    ) -> None:
        """Raise the specific Permit error if the permit is not currently valid."""
        try:
            self._public.verify(
                bytes.fromhex(permit.signature), permit.signing_payload()
            )
        except (InvalidSignature, ValueError) as exc:
            raise PermitSignatureInvalid("permit signature does not verify") from exc
        if now >= permit.expires_at:
            raise PermitExpired("permit has expired")
        if permit.nonce in used_nonces:
            raise PermitReplayed("permit nonce already used")
        if expected_worker is not None and permit.worker_id != expected_worker:
            raise PermitWorkerMismatch(
                f"permit bound to {permit.worker_id}, not {expected_worker}"
            )
