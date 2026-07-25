from __future__ import annotations

import uuid

from ..domain.scope.models import ScopeDraft, ScopeSnapshot
from .audit import AuditService
from .ports.repositories import ScopeRepository


class ScopeService:
    def __init__(self, repo: ScopeRepository, audit: AuditService) -> None:
        self._repo = repo
        self._audit = audit

    def freeze(self, *, project_id: str, include: tuple[str, ...],
               exclude: tuple[str, ...] = (), ports: tuple[int, ...] = (443,),
               approved_by: str) -> ScopeSnapshot:
        draft = ScopeDraft(project_id=project_id, include=include, exclude=exclude, ports=ports)
        snapshot = draft.freeze(
            snapshot_id=f"scope-{uuid.uuid4().hex[:12]}",
            approved_by=approved_by,
        )
        self._repo.add_snapshot(snapshot)
        self._audit.record(
            actor=approved_by, action="scope.frozen",
            resource_type="scope_snapshot", resource_id=snapshot.id,
            payload={"project_id": project_id, "digest": snapshot.digest},
        )
        return snapshot
