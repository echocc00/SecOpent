"""Production hardening tests (§3.8): key rotation, audit HMAC, backup, log redaction."""
from __future__ import annotations

import sqlite3
from dataclasses import replace

from secopent.application.audit import AuditService, chain_hmac, verify_chain_hmac
from secopent.application.secret_store import SecretStore
from secopent.application.signing_keys import SigningKeyService
from secopent.domain.audit.models import GENESIS_HASH, AuditEvent
from secopent.domain.common.canonical import utc_now
from secopent.infrastructure.logging_setup import _redact_processor
from secopent.infrastructure.secrets.encrypted_file_backend import EncryptedFileBackend
from secopent.infrastructure.signing.ed25519 import Ed25519KeyProvider
from secopent.interfaces.cli.main import _cmd_backup

# --- Key rotation ---


def test_key_rotation_archives_old_key() -> None:
    service = SigningKeyService(
        secret_store=SecretStore(EncryptedFileBackend()),
        key_provider=Ed25519KeyProvider(),
    )
    old = service.create_key("default", now=utc_now())
    old_public = old.public_key
    new = service.rotate(old.key_id, now=utc_now())

    assert new.key_id != old.key_id
    # Old key archived but retained (its public key still verifies old sigs).
    assert service.get(old.key_id).archived is True
    assert service.get(old.key_id).public_key == old_public
    # New signatures use the new key.
    assert service.default_key_id() == new.key_id


# --- Audit chain HMAC ---


class _InMemAuditRepo:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def add(self, event: AuditEvent) -> None:
        self.events.append(event)

    def list_events(self) -> list[AuditEvent]:
        return list(self.events)

    def last_hash(self) -> str:
        return (
            self.events[-1].event_hash.removeprefix("sha256:")
            if self.events
            else GENESIS_HASH
        )


def test_audit_chain_hmac_detects_tamper() -> None:
    repo = _InMemAuditRepo()
    service = AuditService(repo)
    service.record(actor="a", action="x", resource_type="r", resource_id="1", payload={})
    service.record(actor="a", action="y", resource_type="r", resource_id="2", payload={})

    key = b"audit-secret-key"
    mac = chain_hmac(repo.list_events(), key)
    assert verify_chain_hmac(repo.list_events(), key, mac)

    # Tampering with a stored event hash changes the keyed MAC.
    tampered = list(repo.list_events())
    tampered[0] = replace(tampered[0], event_hash="sha256:" + "0" * 64)
    assert not verify_chain_hmac(tampered, key, mac)


# --- Backup CLI ---


def test_backup_cli_creates_snapshot(tmp_path) -> None:  # type: ignore[no-untyped-def]
    db = tmp_path / "test.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE t (x)")
    conn.execute("INSERT INTO t VALUES (1)")
    conn.commit()
    conn.close()

    out = tmp_path / "backups"
    assert _cmd_backup(str(db), str(out)) == 0
    backups = list(out.glob("secopent-backup-*.db"))
    assert len(backups) == 1
    # The snapshot is a valid SQLite db with the data.
    check = sqlite3.connect(str(backups[0]))
    assert check.execute("SELECT x FROM t").fetchone()[0] == 1
    check.close()


def test_backup_cli_missing_db(tmp_path) -> None:  # type: ignore[no-untyped-def]
    assert _cmd_backup(str(tmp_path / "nope.db"), str(tmp_path / "out")) == 1


# --- Log redaction ---


def test_log_redaction_masks_sensitive_keys() -> None:
    event = {"password": "hunter2", "token": "abc", "msg": "hello"}
    result = _redact_processor(None, "info", event)  # type: ignore[arg-type]
    assert result["password"] == "[REDACTED]"
    assert result["token"] == "[REDACTED]"
    assert result["msg"] == "hello"
