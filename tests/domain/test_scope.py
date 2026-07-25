from __future__ import annotations

import pytest

from secopent.domain.common.errors import DomainValidationError
from secopent.domain.scope.models import ScopeDraft, ScopeLimits


def test_scope_freeze_normalizes_and_prioritizes_deny() -> None:
    draft = ScopeDraft(
        project_id="project-1",
        include=("HTTPS://Example.Test:443/api", "192.0.2.0/28"),
        exclude=("https://example.test/api/admin", "192.0.2.7"),
        ports=(443, 8443),
        limits=ScopeLimits(requests_per_second=5, concurrency=3, max_requests=1000),
    )
    snapshot = draft.freeze(snapshot_id="scope-1", approved_by="user-1")
    assert snapshot.includes_url("https://example.test/api/users")
    assert not snapshot.includes_url("https://example.test/api/admin/delete")
    assert snapshot.includes_ip("192.0.2.5")
    assert not snapshot.includes_ip("192.0.2.7")
    assert snapshot.includes_port(443)
    assert not snapshot.includes_port(22)
    assert snapshot.digest.startswith("sha256:")


def test_scope_rejects_invalid_port() -> None:
    with pytest.raises(DomainValidationError):
        ScopeDraft(project_id="p", include=("https://example.test",), ports=(0,))


def test_scope_rejects_empty_include() -> None:
    with pytest.raises(DomainValidationError):
        ScopeDraft(project_id="p", include=())


def test_scope_limits_must_be_positive() -> None:
    with pytest.raises(DomainValidationError):
        ScopeLimits(requests_per_second=0, concurrency=1, max_requests=100)


def test_scope_snapshot_immutable() -> None:
    draft = ScopeDraft(project_id="p", include=("https://example.test",))
    snapshot = draft.freeze(snapshot_id="s", approved_by="u")
    with pytest.raises(AttributeError):
        snapshot.include = ("other",)  # type: ignore[misc]
