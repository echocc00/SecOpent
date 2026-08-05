"""AuditRecorder port: anything with a record() method (W3-A T1).

Promoted out of emergency_stop.py so both EmergencyStop and CanaryTokenManager
can depend on the port without coupling to each other. The shared signed
AuditChain satisfies it (as does the DB-backed AuditService), so
security-relevant events - canary generation/verification, emergency trigger -
land in the tamper-evident chain.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class AuditRecorder(Protocol):
    """Append-only audit sink (AuditService or signed AuditChain both satisfy)."""

    def record(
        self,
        *,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        payload: dict[str, object],
        session: Any = None,
    ) -> object: ...
