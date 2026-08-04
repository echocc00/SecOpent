# src/secopent/infrastructure/secrets/persistent_file_backend.py
"""Persistent encrypted-at-rest secret backend (Fernet) - NAS hardening (v0.1.5).

Unlike ``EncryptedFileBackend`` (in-memory only, secrets lost on restart), this
backend persists encrypted secrets to disk so signed Cases/AppModels stay
verifiable after a restart. The Fernet master key lives in a SEPARATE file
(0600) so a store-file leak alone does not expose plaintext.

Files (both 0600, atomic writes):
- ``store_path``: JSON ``{secret_ref: fernet_token}`` - the encrypted secrets.
- ``key_path``:   single-line base64 Fernet key (auto-generated on first start).

The key file is the escrow - losing it makes every stored secret unrecoverable.
Back it up independently (see docs/ops/backup-restore.md); never co-locate it
with the store file.

Env wiring (see ``interfaces.api.main._build_secret_backend``):
- ``SECOPTENT_SECRET_STORE_PATH``: path to the encrypted store file.
- ``SECOPTENT_SECRET_KEY_PATH``:   path to the Fernet key file.

When either is unset the app falls back to ``EncryptedFileBackend`` (in-memory,
dev/test) and secrets do not survive restart - the operator is warned via logs.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet


class PersistentEncryptedFileBackend:
    """Disk-persisted Fernet secret store; survives restart, 0600 file perms."""

    def __init__(
        self,
        store_path: Path,
        key_path: Path,
        *,
        env_key: str | None = None,
    ) -> None:
        self._store_path = store_path
        self._key_path = key_path
        self._env_key = env_key
        self._key = self._load_or_create_key()
        self._fernet = Fernet(self._key)
        self._store: dict[str, str] = self._load_store()

    def _load_or_create_key(self) -> bytes:
        """Load the Fernet key.

        Priority: (1) ``env_key`` env var (operator/KMS-injected, never written
        to disk); (2) ``key_path`` file (read if present, else generated +
        persisted 0600). An invalid env value raises ValueError at startup so a
        misconfigured key fails fast rather than silently regenerating.
        """
        if self._env_key is not None:
            raw = os.environ.get(self._env_key)
            if raw:
                key = raw.strip().encode("utf-8")
                Fernet(key)  # validates format; raises ValueError on garbage
                return key
        if self._key_path.exists():
            return self._key_path.read_bytes().strip()
        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        self._atomic_write(self._key_path, key)
        os.chmod(self._key_path, 0o600)
        return key

    def key_bytes(self) -> bytes:
        """The current Fernet master key (for export/rotation auditing)."""
        return self._key


    def _load_store(self) -> dict[str, str]:
        if not self._store_path.exists():
            return {}
        try:
            data = json.loads(self._store_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # A corrupt/unreadable store is treated as empty rather than crashing
            # startup; the operator restores from backup. The signing-key service
            # logs a warning when its expected keys are absent after a restart.
            return {}
        return {str(k): str(v) for k, v in data.items()}

    def _flush(self) -> None:
        """Atomically persist the full store (0600)."""
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(self._store, ensure_ascii=False).encode("utf-8")
        self._atomic_write(self._store_path, text)
        os.chmod(self._store_path, 0o600)

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        """Write via a same-directory temp file + rename (crash-safe on POSIX)."""
        fd, tmp = tempfile.mkstemp(
            dir=str(path.parent), prefix=".tmp-", suffix=path.name
        )
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
        except Exception:
            Path(tmp).unlink(missing_ok=True)
            raise

    def put(self, secret_ref: str, value: str) -> None:
        self._store[secret_ref] = self._fernet.encrypt(value.encode("utf-8")).decode()
        self._flush()

    def get(self, secret_ref: str) -> str | None:
        token = self._store.get(secret_ref)
        if token is None:
            return None
        return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")

    def delete(self, secret_ref: str) -> None:
        if secret_ref in self._store:
            self._store.pop(secret_ref, None)
            self._flush()

    def encrypted_token(self, secret_ref: str) -> str | None:
        """Expose the stored (encrypted) token - for verifying encryption at rest."""
        return self._store.get(secret_ref)
