from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum

from ..common.canonical import utc_now
from ..common.errors import DomainValidationError


class ProjectStatus(StrEnum):
    ACTIVE = "active"
    ARCHIVED = "archived"


@dataclass(frozen=True, slots=True)
class Project:
    id: str
    name: str
    status: ProjectStatus
    created_at: datetime

    @classmethod
    def create(cls, *, project_id: str, name: str) -> Project:
        normalized_id = project_id.strip()
        normalized_name = name.strip()
        if not normalized_id:
            raise DomainValidationError("project id must not be empty")
        if not normalized_name:
            raise DomainValidationError("project name must not be empty")
        return cls(normalized_id, normalized_name, ProjectStatus.ACTIVE, utc_now())

    def archive(self) -> Project:
        """ACTIVE -> ARCHIVED. Idempotent on ARCHIVED (no-op)."""
        if self.status is ProjectStatus.ARCHIVED:
            return self
        return replace(self, status=ProjectStatus.ARCHIVED)

    def reactivate(self) -> Project:
        """ARCHIVED -> ACTIVE. Rejects an already-active project."""
        if self.status is ProjectStatus.ACTIVE:
            raise DomainValidationError("project is already active")
        return replace(self, status=ProjectStatus.ACTIVE)
