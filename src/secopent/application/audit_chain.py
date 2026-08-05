# src/secopent/application/audit_chain.py
"""AuditChain: signed hash chain with rotation + GDPR redaction (§12).

Upgrades the M0 hash chain: every event is also Ed25519-signed (the audit key is
independent of the update-bundle key). Permit nonces are recorded so a replayed
permit is detectable. Log rotation does NOT break the chain - the rotation event
references the prior tail (``previous_chain_tail_hash``) and continues from it.
GDPR redaction masks PII plaintext on export while preserving each event's hash
commitment and recording the deletion in the chain itself.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Protocol, runtime_checkable

from ..domain.audit.models import GENESIS_HASH, AuditEvent
from .ports.audit_chain import SignedAuditEventStore


@dataclass(frozen=True, slots=True)
class SignedAuditEvent:
    """An audit event plus its Ed25519 signature (over the event hash)."""

    event: AuditEvent
    signature: str


@runtime_checkable
class AuditSigner(Protocol):
    """Signs/verifies audit event hashes (Ed25519 in infrastructure)."""

    def sign(self, message: bytes) -> str: ...

    def verify(self, message: bytes, signature: str) -> bool: ...


class AuditChain:
    """A signed, tamper-evident audit hash chain."""

    def __init__(
        self,
        signer: AuditSigner,
        *,
        store: SignedAuditEventStore | None = None,
    ) -> None:
        self._signer = signer
        self._store = store
        self._events: list[SignedAuditEvent] = []
        self._tail = GENESIS_HASH  # bare hex of the last event hash
        self._counter = 0
        self._redactions: dict[str, frozenset[str]] = {}
        if store is not None:
            self._load_from_store(store)

    def _load_from_store(self, store: SignedAuditEventStore) -> None:
        """Rebuild in-memory state from persisted events (H6 restart survival)."""
        loaded = store.load_all()
        self._events = list(loaded)
        if loaded:
            self._tail = loaded[-1].event.event_hash.removeprefix("sha256:")
            self._counter = len(loaded)
        # Re-derive GDPR redaction state from persisted gdpr.redacted events.
        for signed in loaded:
            if signed.event.action == "gdpr.redacted":
                eid = signed.event.payload.get("redacted_event_id")
                keys = signed.event.payload.get("keys")
                if isinstance(eid, str) and isinstance(keys, list):
                    self._redactions[eid] = frozenset(str(k) for k in keys)

    def record(
        self,
        *,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        payload: dict[str, object],
        permit_nonce: str | None = None,
        session: Any = None,
    ) -> SignedAuditEvent:
        """Append a signed event, continuing the hash chain.

        When ``session`` is provided, the signed event is appended via that
        session WITHOUT committing (v4 same-tx refactor - the caller owns the
        transaction so the signed audit insert joins the business-write
        transaction, eliminating cross-connection double-write contention).
        """
        self._counter += 1
        body = dict(payload)
        if permit_nonce is not None:
            body["permit_nonce"] = permit_nonce
        event = AuditEvent.create(
            event_id=f"evt-{self._counter}",
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            payload=body,
            previous_hash=self._tail,
        )
        signature = self._signer.sign(event.event_hash.encode("utf-8"))
        signed = SignedAuditEvent(event=event, signature=signature)
        self._events.append(signed)
        self._tail = event.event_hash.removeprefix("sha256:")
        if self._store is not None:
            self._store.append(signed, session=session)
        return signed

    def record_permit_nonce(
        self, *, actor: str, job_id: str, permit_nonce: str
    ) -> SignedAuditEvent:
        """Record a permit's nonce so a replay is detectable."""
        return self.record(
            actor=actor,
            action="permit.used",
            resource_type="permit",
            resource_id=job_id,
            payload={"job_id": job_id},
            permit_nonce=permit_nonce,
        )

    def permit_nonces(self) -> set[str]:
        """All permit nonces recorded in the chain."""
        return {
            str(e.event.payload["permit_nonce"])
            for e in self._events
            if "permit_nonce" in e.event.payload
        }

    def verify(self) -> bool:
        """Verify the hash chain AND every event signature."""
        events = [s.event for s in self._events]
        if not AuditEvent.verify_chain(events):
            return False
        return all(
            self._signer.verify(s.event.event_hash.encode("utf-8"), s.signature)
            for s in self._events
        )

    def rotate(self) -> SignedAuditEvent:
        """Rotate the log: the new segment continues from the prior tail."""
        return self.record(
            actor="audit_chain",
            action="audit.rotated",
            resource_type="audit_chain",
            resource_id="rotation",
            payload={"previous_chain_tail_hash": self._tail},
        )

    def redact_pii(self, event_id: str, *, keys: frozenset[str]) -> SignedAuditEvent:
        """GDPR: mark PII keys redacted; preserve the hash; audit the deletion."""
        self._redactions[event_id] = keys
        return self.record(
            actor="audit_chain",
            action="gdpr.redacted",
            resource_type="audit_event",
            resource_id=event_id,
            payload={"redacted_event_id": event_id, "keys": sorted(keys)},
        )

    def export(self, *, redacted: bool = False) -> tuple[AuditEvent, ...]:
        """Export events; when redacted, mask PII keys (hash commitment kept)."""
        if not redacted:
            return tuple(s.event for s in self._events)
        exported: list[AuditEvent] = []
        for signed in self._events:
            keys = self._redactions.get(signed.event.id)
            if keys:
                masked = {
                    key: ("[REDACTED:gdpr]" if key in keys else value)
                    for key, value in signed.event.payload.items()
                }
                exported.append(replace(signed.event, payload=masked))
            else:
                exported.append(signed.event)
        return tuple(exported)

    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(s.event for s in self._events)
