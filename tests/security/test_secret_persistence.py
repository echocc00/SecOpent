# tests/security/test_secret_persistence.py
"""SecretStore metadata persistence across restart (W2-C T2)."""
from __future__ import annotations

from pathlib import Path

from secopent.application.secret_store import SecretStore
from secopent.domain.common.canonical import utc_now
from secopent.infrastructure.secrets.persistent_file_backend import (
    PersistentEncryptedFileBackend,
)


def test_secret_value_and_metadata_survive_restart(tmp_path: Path) -> None:
    """A new SecretStore over the same backend sees both the value and metadata."""
    store_path = tmp_path / "secrets.json"
    key_path = tmp_path / "key"
    backend = PersistentEncryptedFileBackend(store_path, key_path)
    store = SecretStore(backend)
    md = store.register("llm_api_key", "sk-xxx", now=utc_now())

    # Reopen the backend + store = "after restart".
    reloaded = SecretStore(PersistentEncryptedFileBackend(store_path, key_path))
    assert reloaded.resolve(md.secret_ref) == "sk-xxx"
    reloaded_md = reloaded.metadata(md.secret_ref)
    assert reloaded_md is not None
    assert reloaded_md.name == "llm_api_key"
    assert reloaded_md.secret_ref == md.secret_ref


def test_revoke_deletes_value_and_metadata(tmp_path: Path) -> None:
    store_path = tmp_path / "secrets.json"
    key_path = tmp_path / "key"
    backend = PersistentEncryptedFileBackend(store_path, key_path)
    store = SecretStore(backend)
    md = store.register("tmp", "v", now=utc_now())

    store.revoke(md.secret_ref)

    reloaded = SecretStore(PersistentEncryptedFileBackend(store_path, key_path))
    assert reloaded.metadata(md.secret_ref) is None
    import pytest

    from secopent.application.secret_store import SecretNotFound
    with pytest.raises(SecretNotFound):
        reloaded.resolve(md.secret_ref)
