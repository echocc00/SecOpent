"""TDD tests for the signed AuditChain (M5 Task 4, §12)."""
from __future__ import annotations

from dataclasses import replace

from secopent.application.audit_chain import AuditChain
from secopent.infrastructure.audit.key_manager import AuditKeyManager


def _chain() -> AuditChain:
    return AuditChain(AuditKeyManager())


def test_signed_chain_verifies() -> None:
    chain = _chain()
    chain.record(actor="a", action="x", resource_type="r", resource_id="1", payload={})
    chain.record(actor="a", action="y", resource_type="r", resource_id="2", payload={})
    assert chain.verify() is True


def test_tampered_event_breaks_verification() -> None:
    chain = _chain()
    chain.record(actor="a", action="x", resource_type="r", resource_id="1", payload={"amount": 1})
    chain.record(actor="a", action="y", resource_type="r", resource_id="2", payload={})
    # Tamper with the first event's payload -> its hash no longer matches.
    first = chain._events[0]
    forged = replace(first.event, payload={"amount": 999999})
    chain._events[0] = replace(first, event=forged)
    assert chain.verify() is False


def test_forged_signature_breaks_verification() -> None:
    chain = _chain()
    chain.record(actor="a", action="x", resource_type="r", resource_id="1", payload={})
    first = chain._events[0]
    chain._events[0] = replace(first, signature="00" * 64)
    assert chain.verify() is False


def test_rotation_continues_chain() -> None:
    chain = _chain()
    chain.record(actor="a", action="x", resource_type="r", resource_id="1", payload={})
    tail_before = chain._tail
    rotation = chain.rotate()
    # The rotation event references the prior tail and continues from it.
    assert rotation.event.payload["previous_chain_tail_hash"] == tail_before
    assert rotation.event.previous_hash == tail_before
    # Chain still verifies across the rotation.
    assert chain.verify() is True


def test_permit_nonce_recorded_and_replay_detectable() -> None:
    chain = _chain()
    chain.record_permit_nonce(actor="worker-1", job_id="job-1", permit_nonce="nonce-xyz")
    assert "nonce-xyz" in chain.permit_nonces()
    # A second use of the same nonce is visible to replay detection.
    chain.record_permit_nonce(actor="worker-2", job_id="job-1", permit_nonce="nonce-xyz")
    nonces = [
        e.payload["permit_nonce"] for e in chain.events() if "permit_nonce" in e.payload
    ]
    assert nonces.count("nonce-xyz") == 2  # replay is detectable


def test_gdpr_redaction_masks_pii_but_keeps_chain() -> None:
    chain = _chain()
    signed = chain.record(
        actor="a", action="scan", resource_type="r", resource_id="1",
        payload={"email": "user@example.com", "note": "ok"},
    )
    chain.redact_pii(signed.event.id, keys=frozenset({"email"}))

    # Original events still hold the plaintext (hash commitment intact)...
    original = chain.events()
    assert original[0].payload["email"] == "user@example.com"
    assert chain.verify() is True

    # ...but the redacted export masks it, and the deletion is itself audited.
    redacted = chain.export(redacted=True)
    assert redacted[0].payload["email"] == "[REDACTED:gdpr]"
    assert redacted[0].payload["note"] == "ok"
    assert any(e.action == "gdpr.redacted" for e in chain.events())
