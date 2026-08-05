from __future__ import annotations

import hashlib
import hmac as _hmac
from typing import Any

from ..domain.audit.models import GENESIS_HASH, AuditEvent
from .ports.repositories import AuditRepository


def chain_hmac(events: list[AuditEvent], key: bytes) -> str:
    """Keyed HMAC over the audit chain's event hashes (§3.8 tamper upgrade).

    The hash chain already detects tampering; this adds keyed authenticity -
    it proves the chain was produced by a holder of ``key``. Computed over the
    ordered event hashes, so any reorder/edit/insert changes the MAC.
    """
    mac = _hmac.new(key, digestmod=hashlib.sha256)
    for event in events:
        mac.update(event.event_hash.encode("utf-8"))
    return "hmac-sha256:" + mac.hexdigest()


def verify_chain_hmac(events: list[AuditEvent], key: bytes, expected: str) -> bool:
    """Constant-time check of a chain HMAC."""
    return _hmac.compare_digest(chain_hmac(events, key), expected)


class AuditService:
    def __init__(self, repo: AuditRepository) -> None:
        self._repo = repo

    def record(self, *, actor: str, action: str, resource_type: str,
               resource_id: str, payload: dict[str, object],
               session: Any = None) -> AuditEvent:
        # ``session`` is accepted for AuditRecorder Protocol compatibility (the
        # canary/oracle pass it through). AuditService ignores it - the repo is
        # already bound to the correct session at construction time.
        previous = self._repo.last_hash() or GENESIS_HASH
        event = AuditEvent.create(
            event_id=f"evt-{len(self._repo.list_events()) + 1}",
            actor=actor, action=action, resource_type=resource_type,
            resource_id=resource_id, payload=payload, previous_hash=previous,
        )
        self._repo.add(event)
        return event

    def chain_hmac(self, key: bytes) -> str:
        """Keyed HMAC over the current chain (§3.8)."""
        return chain_hmac(self._repo.list_events(), key)

    @staticmethod
    def verify(events: list[AuditEvent]) -> bool:
        return AuditEvent.verify_chain(events)
