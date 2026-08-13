"""Application layer: ScopeService.validate + freeze cloud_accounts (MCP §13).

``validate`` normalizes a draft without persisting and reports per-target
errors instead of raising - the scope_draft/scope_validate tool contract.
"""
from __future__ import annotations

import pytest

from secopent.application.audit import AuditService
from secopent.application.scopes import ScopeService
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.scope.models import ScopeSnapshot


@pytest.fixture
def service(memory_repositories):  # noqa: ANN001
    return ScopeService(
        memory_repositories.scopes, AuditService(memory_repositories.audit)
    )


def test_validate_normalizes_targets(service) -> None:  # noqa: ANN001
    result = service.validate(
        include=["http://Example.com/", "8.8.8.8", "example.org"],
        exclude=["http://evil.example.com/"],
        ports=[80, 443],
        cloud_accounts=["AWS:123456789012"],
    )
    assert result.ok
    assert "http://example.com/" in result.include
    assert "example.org" in result.include
    assert "8.8.8.8" in result.include
    assert result.ports == (80, 443)
    assert result.cloud_accounts == ("aws:123456789012",)


def test_validate_reports_bad_targets_without_raising(service) -> None:  # noqa: ANN001
    result = service.validate(
        include=["http://example.com", "", "http://"],
        ports=[443, 99999],
        cloud_accounts=["no-colon"],
    )
    assert not result.ok
    errors = {(field, index, raw): err for field, index, raw, err in result.errors}
    assert ("include", 1, "") in errors
    assert ("include", 2, "http://") in errors
    assert ("ports", 1, "99999") in errors
    assert ("cloud_accounts", 0, "no-colon") in errors
    # Valid items survive; invalid ones are dropped from the normalized lists.
    assert "http://example.com/" in result.include
    assert result.ports == (443,)


def test_validate_empty_include_is_ok_by_contract(service) -> None:  # noqa: ANN001
    """validate never raises (the tool reports problems); freeze stays strict."""
    result = service.validate(include=[])
    assert result.ok
    with pytest.raises(DomainValidationError):
        service.freeze(
            project_id="p1", include=(), approved_by="tester"
        )


def test_freeze_persists_cloud_accounts(service) -> None:  # noqa: ANN001
    snapshot = service.freeze(
        project_id="p1",
        include=["http://example.com"],
        approved_by="tester",
        cloud_accounts=["AWS:123456789012"],
    )
    assert isinstance(snapshot, ScopeSnapshot)
    assert snapshot.cloud_accounts == ("aws:123456789012",)


def test_freeze_still_audits(service, memory_repositories) -> None:  # noqa: ANN001
    service.freeze(project_id="p1", include=["http://example.com"],
                   approved_by="tester")
    actions = [e.action for e in memory_repositories.audit.events]
    assert "scope.frozen" in actions