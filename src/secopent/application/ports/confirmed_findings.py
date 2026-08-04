"""ConfirmedFindingRepository port (W3-A T3)."""
from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from ...domain.verification.models import ConfirmedFinding


@runtime_checkable
class ConfirmedFindingRepository(Protocol):
    """Persisted store for oracle-confirmed findings.

    ``candidate_id`` is the source Finding's id; a ConfirmedFinding is the
    oracle-verified promotion of that finding (N/N reproduction succeeded).
    """

    def add(self, confirmed: ConfirmedFinding) -> None: ...
    def get(self, candidate_id: str) -> ConfirmedFinding | None: ...
    def list_for_candidates(
        self, candidate_ids: Sequence[str]
    ) -> tuple[ConfirmedFinding, ...]: ...
