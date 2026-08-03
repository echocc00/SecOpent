# src/secopent/application/signing_keys.py
"""SigningKeyService: server-held Ed25519 signing keys via SecretStore (decision H).

Multiple named signing keys are supported. Private key material is stored
(encrypted at rest) in the SecretStore and only ever resolved transiently to
produce a signature - it is never returned by any query, so the frontend can
request a signature but never hold a private key (LLM/frontend boundary).

Crypto operations live behind the ``KeyProvider`` protocol (implemented in
infrastructure) so the application layer stays free of ``cryptography``.

NAS persistence (v0.1.5): when ``key_metadata_path`` is supplied, the public
metadata (key_id -> public_key/name/created_at/archived) is persisted to disk
(0600) so signatures stay verifiable after a restart - the private material is
recovered from the SecretStore's persistent backend, the public metadata from
this file. ``ensure_default_key`` is idempotent across restarts. Without the
path the service is in-memory only (dev/test).
"""
from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
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
    """Public information about a signing key (deliberately no private key).

    ``archived`` marks a rotated-out key: it is retained (its public key can
    still verify old signatures) but is never used for new signatures.
    """

    key_id: str
    name: str
    public_key: str
    created_at: datetime
    archived: bool = False


class SigningKeyService:
    """Manage named signing keys; private material stays in the SecretStore."""

    def __init__(
        self,
        secret_store: SecretStore,
        key_provider: KeyProvider,
        key_metadata_path: Path | None = None,
    ) -> None:
        self._secrets = secret_store
        self._provider = key_provider
        self._metadata_path = key_metadata_path
        self._keys: dict[str, SigningKeyInfo] = self._load_metadata()

    def _load_metadata(self) -> dict[str, SigningKeyInfo]:
        """Rebuild ``_keys`` from the persisted metadata file (if present)."""
        if self._metadata_path is None or not self._metadata_path.exists():
            return {}
        try:
            data = json.loads(self._metadata_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
        out: dict[str, SigningKeyInfo] = {}
        for entry in data.get("keys", []):
            try:
                out[entry["key_id"]] = SigningKeyInfo(
                    key_id=entry["key_id"],
                    name=entry["name"],
                    public_key=entry["public_key"],
                    created_at=datetime.fromisoformat(entry["created_at"]),
                    archived=bool(entry.get("archived", False)),
                )
            except (KeyError, ValueError, TypeError):
                continue
        return out

    def _flush_metadata(self) -> None:
        """Atomically persist ``_keys`` (public metadata only, 0600)."""
        if self._metadata_path is None:
            return
        payload = {
            "keys": [
                {
                    "key_id": k.key_id,
                    "name": k.name,
                    "public_key": k.public_key,
                    "created_at": k.created_at.isoformat(),
                    "archived": k.archived,
                }
                for k in self._keys.values()
            ]
        }
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._metadata_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            dir=str(self._metadata_path.parent),
            prefix=".tmp-",
            suffix=self._metadata_path.name,
        )
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(tmp, self._metadata_path)
        except Exception:
            Path(tmp).unlink(missing_ok=True)
            raise
        os.chmod(self._metadata_path, 0o600)

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
        self._flush_metadata()
        return info

    def ensure_default_key(self, name: str, *, now: datetime) -> SigningKeyInfo:
        """Return the existing non-archived key with this name, or create one.

        Idempotent across restarts: a non-archived key named ``name`` is reused
        (its private material is recovered from the SecretStore's persistent
        backend). This keeps the default signing key stable so previously
        signed Cases stay verifiable after a restart.
        """
        for info in self._keys.values():
            if info.name == name and not info.archived:
                return info
        return self.create_key(name, now=now)

    def list_keys(self) -> list[SigningKeyInfo]:
        return [self._keys[key_id] for key_id in sorted(self._keys)]

    def get(self, key_id: str) -> SigningKeyInfo:
        info = self._keys.get(key_id)
        if info is None:
            raise SigningKeyNotFound(f"unknown signing key: {key_id}")
        return info

    def default_key_id(self) -> str | None:
        """The newest non-archived key (insertion order), or None."""
        active = [k for k in self._keys.values() if not k.archived]
        return active[-1].key_id if active else None

    def rotate(self, old_key_id: str, *, now: datetime) -> SigningKeyInfo:
        """Rotate a key: create a new key and archive the old one (§3.8).

        The old key is archived but RETAINED so its public key can still verify
        signatures made before rotation; new signatures use the new key.
        """
        old = self.get(old_key_id)
        new_info = self.create_key(f"{old.name}-next", now=now)
        self._keys[old_key_id] = replace(old, archived=True)
        self._flush_metadata()
        return new_info

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
