from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime

from ..common.canonical import canonical_json, utc_now
from ..common.errors import DomainValidationError

GENESIS_HASH = "0" * 64
_SECRET_KEYS = {"password", "secret", "token", "authorization", "api_key", "cookie"}


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Immutable audit event linked into a tamper-evident hash chain.

    ``previous_hash`` stores the bare 64-hex hash (no ``sha256:`` prefix) of the
    prior event, or ``GENESIS_HASH`` for the first event. ``event_hash`` stores the
    same digest with the ``sha256:`` prefix. ``verify_chain`` tolerates both forms
    when comparing, but new events should follow the bare-hex convention for
    ``previous_hash`` (matches ``AuditRepository.last_hash``).
    """

    id: str
    actor: str
    action: str
    resource_type: str
    resource_id: str
    payload: dict[str, object]
    previous_hash: str
    event_hash: str
    occurred_at: datetime

    @classmethod
    def create(cls, *, event_id: str, actor: str, action: str, resource_type: str,
               resource_id: str, payload: dict[str, object], previous_hash: str) -> AuditEvent:
        if not all((event_id, actor, action, resource_type, resource_id)):
            raise DomainValidationError("audit event fields must not be empty")
        _check_no_secret(payload)
        occurred_at = utc_now()
        body = {
            "id": event_id,
            "actor": actor,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "payload": payload,
            "previous_hash": previous_hash,
            "occurred_at": occurred_at,
        }
        event_hash = "sha256:" + hashlib.sha256(
            canonical_json(body).encode("utf-8")
        ).hexdigest()
        return cls(event_id, actor, action, resource_type, resource_id, payload,
                   previous_hash, event_hash, occurred_at)

    @staticmethod
    def verify_chain(events: list[AuditEvent]) -> bool:
        previous = GENESIS_HASH
        for event in events:
            if previous.startswith("sha256:"):
                expected_prev = previous.removeprefix("sha256:")
            else:
                expected_prev = previous
            if event.previous_hash != expected_prev:
                return False
            body = {
                "id": event.id,
                "actor": event.actor,
                "action": event.action,
                "resource_type": event.resource_type,
                "resource_id": event.resource_id,
                "payload": event.payload,
                "previous_hash": event.previous_hash,
                "occurred_at": event.occurred_at,
            }
            recomputed = "sha256:" + hashlib.sha256(
                canonical_json(body).encode("utf-8")
            ).hexdigest()
            if recomputed != event.event_hash:
                return False
            previous = event.event_hash.removeprefix("sha256:")
        return True


def _check_no_secret(payload: dict[str, object]) -> None:
    for key in payload:
        if key.lower() in _SECRET_KEYS:
            raise DomainValidationError(f"secret key '{key}' must not appear in audit payload")
