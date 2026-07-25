# tests/domain/test_audit.py
from __future__ import annotations
import pytest
from secopent.domain.audit.models import AuditEvent
from secopent.domain.common.errors import DomainValidationError


def test_audit_first_event_uses_genesis_previous() -> None:
    event = AuditEvent.create(
        event_id="e1",
        actor="user-1",
        action="scope.approved",
        resource_type="scope_snapshot",
        resource_id="s1",
        payload={"approved_by": "user-1"},
        previous_hash="0" * 64,
    )
    assert event.event_hash.startswith("sha256:")
    assert event.previous_hash == "0" * 64


def test_audit_chain_links_hashes() -> None:
    first = AuditEvent.create(
        event_id="e1", actor="u", action="a", resource_type="r", resource_id="r1",
        payload={}, previous_hash="0" * 64,
    )
    second = AuditEvent.create(
        event_id="e2", actor="u", action="b", resource_type="r", resource_id="r2",
        payload={}, previous_hash=first.event_hash.removeprefix("sha256:"),
    )
    assert second.previous_hash == first.event_hash.removeprefix("sha256:")


def test_audit_rejects_empty_fields() -> None:
    with pytest.raises(DomainValidationError):
        AuditEvent.create(
            event_id="", actor="u", action="a", resource_type="r", resource_id="r1",
            payload={}, previous_hash="0" * 64,
        )


def test_audit_rejects_secret_in_payload() -> None:
    with pytest.raises(DomainValidationError, match="secret"):
        AuditEvent.create(
            event_id="e1", actor="u", action="a", resource_type="r", resource_id="r1",
            payload={"password": "hunter2"}, previous_hash="0" * 64,
        )


def test_audit_detects_tamper() -> None:
    first = AuditEvent.create(
        event_id="e1", actor="u", action="a", resource_type="r", resource_id="r1",
        payload={}, previous_hash="0" * 64,
    )
    second = AuditEvent.create(
        event_id="e2", actor="u", action="b", resource_type="r", resource_id="r2",
        payload={}, previous_hash=first.event_hash.removeprefix("sha256:"),
    )
    assert AuditEvent.verify_chain([first, second]) is True
    tampered = AuditEvent(
        id=second.id, actor=second.actor, action="tampered", resource_type=second.resource_type,
        resource_id=second.resource_id, payload=second.payload, previous_hash=second.previous_hash,
        event_hash=second.event_hash, occurred_at=second.occurred_at,
    )
    assert AuditEvent.verify_chain([first, tampered]) is False
