# tests/infrastructure/test_persistent_secret_backend.py
"""PersistentEncryptedFileBackend: real file persistence + env key (W2-C T1)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet, InvalidToken

from secopent.infrastructure.secrets.persistent_file_backend import (
    PersistentEncryptedFileBackend,
)


def test_put_get_survives_restart(tmp_path: Path) -> None:
    """A new instance pointing at the same files sees the stored secret."""
    store = tmp_path / "secrets.json"
    key = tmp_path / "key"
    backend = PersistentEncryptedFileBackend(store, key)
    backend.put("secret:abc", "plaintext-value")

    reloaded = PersistentEncryptedFileBackend(store, key)
    assert reloaded.get("secret:abc") == "plaintext-value"


def test_key_injected_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """SECOPTENT_SECRET_KEY supplies the Fernet key; no key file is written."""
    explicit = Fernet.generate_key()
    monkeypatch.setenv("SECOPTENT_SECRET_KEY", explicit.decode())
    key_file = tmp_path / "key"
    backend = PersistentEncryptedFileBackend(
        tmp_path / "secrets.json", key_file, env_key="SECOPTENT_SECRET_KEY",
    )
    assert backend.key_bytes() == explicit
    assert not key_file.exists()  # env-supplied key is never written to disk


def test_env_key_takes_precedence_over_key_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When both env and key file exist, env wins (operator can rotate by env)."""
    file_key = Fernet.generate_key()
    key_file = tmp_path / "key"
    key_file.write_bytes(file_key)
    env_key = Fernet.generate_key()
    monkeypatch.setenv("SECOPTENT_SECRET_KEY", env_key.decode())

    backend = PersistentEncryptedFileBackend(
        tmp_path / "secrets.json", key_file, env_key="SECOPTENT_SECRET_KEY",
    )
    backend.put("secret:x", "v")
    # Decrypt with the env key, not the file key.
    assert Fernet(env_key).decrypt(backend.encrypted_token("secret:x").encode()).decode() == "v"
    with pytest.raises(InvalidToken):
        Fernet(file_key).decrypt(backend.encrypted_token("secret:x").encode())


@pytest.mark.skipif(sys.platform == "win32", reason="Unix file perms not honored on Windows")
def test_key_file_chmod_0600(tmp_path: Path) -> None:
    key = tmp_path / "key"
    PersistentEncryptedFileBackend(tmp_path / "secrets.json", key)
    assert (key.stat().st_mode & 0o777) == 0o600


def test_invalid_env_key_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECOPTENT_SECRET_KEY", "not-a-valid-fernet-key")
    with pytest.raises(ValueError):
        PersistentEncryptedFileBackend(
            tmp_path / "secrets.json", tmp_path / "key", env_key="SECOPTENT_SECRET_KEY",
        )
