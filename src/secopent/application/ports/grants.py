"""Grant persistence port (v0.6.0 spec §3.2)."""
from __future__ import annotations

from typing import Protocol

from ...domain.grants.models import EngagementGrant


class GrantRepository(Protocol):
    def add(self, grant: EngagementGrant) -> None: ...
    def get(self, grant_id: str) -> EngagementGrant | None: ...
    def list_for_project(self, project_id: str) -> tuple[EngagementGrant, ...]: ...