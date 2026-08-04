# src/secopent/infrastructure/safety/permit_revoker.py
"""In-memory permit revocation store (W2-A Task 1).

Replaces ``NullPermitRevoker`` (which returned 0). ``EmergencyStop.trigger``
calls ``revoke_unused()`` to invalidate issued-but-unused permits within
their TTL window. Production may later swap this for a DB-backed store;
the ``PermitRevoker`` Protocol in ``application/emergency_stop.py`` stays
stable.
"""
from __future__ import annotations

from secopent.application.emergency_stop import PermitRevoker


class InMemoryPermitRevoker(PermitRevoker):
    """Tracks issued permit nonces and revokes the unused ones on demand."""

    def __init__(self) -> None:
        self._issued: dict[str, bool] = {}  # nonce -> used?
        self._revoked: set[str] = set()

    def record_issued(self, nonce: str, *, used: bool = False) -> None:
        if nonce not in self._revoked:
            self._issued[nonce] = used

    def record_used(self, nonce: str) -> None:
        if nonce in self._issued:
            self._issued[nonce] = True

    def is_revoked(self, nonce: str) -> bool:
        return nonce in self._revoked

    def revoke_unused(self) -> int:
        pending = [n for n, used in self._issued.items() if not used]
        for nonce in pending:
            self._revoked.add(nonce)
            self._issued.pop(nonce, None)
        return len(pending)
