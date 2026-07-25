from __future__ import annotations
from ..domain.audit.models import AuditEvent, GENESIS_HASH
from .ports.repositories import AuditRepository


class AuditService:
    def __init__(self, repo: AuditRepository) -> None:
        self._repo = repo

    def record(self, *, actor: str, action: str, resource_type: str,
               resource_id: str, payload: dict[str, object]) -> AuditEvent:
        previous = self._repo.last_hash() or GENESIS_HASH
        event = AuditEvent.create(
            event_id=f"evt-{len(self._repo.list_events()) + 1}",
            actor=actor, action=action, resource_type=resource_type,
            resource_id=resource_id, payload=payload, previous_hash=previous,
        )
        self._repo.add(event)
        return event

    @staticmethod
    def verify(events: list[AuditEvent]) -> bool:
        return AuditEvent.verify_chain(events)
