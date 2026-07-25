from __future__ import annotations

from secopent.application.audit import AuditService
from secopent.application.scopes import ScopeService


def test_freeze_scope_persists_snapshot_and_audits(memory_repositories):
    service = ScopeService(memory_repositories.scopes, AuditService(memory_repositories.audit))
    snapshot = service.freeze(
        project_id="p", include=("https://example.test",), exclude=(),
        ports=(443,), approved_by="u",
    )
    assert memory_repositories.scopes.get_snapshot(snapshot.id) == snapshot
    events = memory_repositories.audit.list_events()
    assert len(events) == 1
    assert events[0].action == "scope.frozen"
