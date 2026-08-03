# src/secopent/application/emergency_stop.py
"""EmergencyStop: global kill switch (§12).

When triggered (e.g. a compromise is detected) the stop:
- flips a global switch so no NEW permits are issued;
- revokes unused permits;
- terminates active containers (via an injected terminator; Docker SDK in M5);
- PRESERVES already-produced evidence (never deleted - needed for forensics);
- writes a high-priority audit event.

Dependencies are injected Protocols so the application layer stays free of
Docker/infrastructure coupling.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .audit import AuditService


@runtime_checkable
class PermitRevoker(Protocol):
    """Revokes all not-yet-used permits; returns the count revoked."""

    def revoke_unused(self) -> int: ...


@runtime_checkable
class ContainerTerminator(Protocol):
    """Terminates active execution containers; returns the count terminated."""

    def terminate_active(self) -> int: ...


@dataclass(frozen=True, slots=True)
class EmergencyReport:
    """The outcome of triggering the emergency stop."""

    triggered: bool
    revoked_permits: int
    terminated_containers: int
    evidence_preserved: bool
    actor: str
    reason: str


class EmergencyStop:
    """Global emergency kill switch."""

    def __init__(
        self,
        *,
        permit_revoker: PermitRevoker,
        container_terminator: ContainerTerminator,
        audit: AuditService,
    ) -> None:
        self._permit_revoker = permit_revoker
        self._container_terminator = container_terminator
        self._audit = audit
        self._triggered = False

    @property
    def is_triggered(self) -> bool:
        return self._triggered

    def permits_allowed(self) -> bool:
        """No new permits may be issued once the stop is triggered."""
        return not self._triggered

    def trigger(self, *, actor: str, reason: str) -> EmergencyReport:
        """Activate the kill switch; idempotent on the switch itself.

        Container termination failures are captured in the report (with a
        negative count) rather than raising - the switch must still flip and
        the audit event must still land even if Docker is unreachable. The
        negative ``terminated_containers`` signals the operator that manual
        verification is needed.
        """
        self._triggered = True
        revoked = self._permit_revoker.revoke_unused()
        try:
            terminated = self._container_terminator.terminate_active()
        except Exception:  # noqa: BLE001 - kill switch must not fail silently
            terminated = -1  # signals: termination could not be verified
        # Evidence is deliberately preserved for forensics (never deleted).
        self._audit.record(
            actor=actor,
            action="emergency_stop.triggered",
            resource_type="emergency_stop",
            resource_id="global",
            payload={
                "priority": "high",
                "reason": reason,
                "revoked_permits": revoked,
                "terminated_containers": terminated,
                "evidence_preserved": True,
            },
        )
        return EmergencyReport(
            triggered=True,
            revoked_permits=revoked,
            terminated_containers=terminated,
            evidence_preserved=True,
            actor=actor,
            reason=reason,
        )
