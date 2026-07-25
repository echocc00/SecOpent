from __future__ import annotations

import pytest

from secopent.application.audit import AuditService
from secopent.domain.common.errors import DomainValidationError


def test_audit_service_chains_events(memory_repositories):
    service = AuditService(memory_repositories.audit)
    service.record(actor="u", action="a", resource_type="r", resource_id="r1", payload={})
    service.record(actor="u", action="b", resource_type="r", resource_id="r2", payload={})
    events = memory_repositories.audit.list_events()
    assert len(events) == 2
    assert AuditService.verify(events) is True


def test_audit_service_rejects_secret(memory_repositories):
    service = AuditService(memory_repositories.audit)
    with pytest.raises(DomainValidationError, match="secret"):
        service.record(actor="u", action="a", resource_type="r", resource_id="r1",
                       payload={"password": "x"})
