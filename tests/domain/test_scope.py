from __future__ import annotations

from datetime import UTC, datetime

import pytest

from secopent.domain.common.errors import DomainValidationError
from secopent.domain.scope.models import ScopeDraft, ScopeLimits, ScopeSnapshot
from secopent.domain.scope.normalize import normalize_cloud_account


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


# ---------------------------------------------------------------------------
# Cloud-account scope (M1 Task 12, §4.1.1 方案 B)
# ---------------------------------------------------------------------------


def test_normalize_cloud_account_lowercases_provider() -> None:
    assert normalize_cloud_account("AWS:123456789012") == "aws:123456789012"


def test_normalize_cloud_account_strips_whitespace() -> None:
    assert normalize_cloud_account("  gcp : my-project-123  ") == "gcp:my-project-123"


def test_normalize_cloud_account_rejects_missing_colon() -> None:
    with pytest.raises(DomainValidationError):
        normalize_cloud_account("123456789012")


def test_normalize_cloud_account_rejects_empty_provider_or_id() -> None:
    with pytest.raises(DomainValidationError):
        normalize_cloud_account("aws:")
    with pytest.raises(DomainValidationError):
        normalize_cloud_account(":123456789012")


def test_normalize_cloud_account_rejects_invalid_provider_chars() -> None:
    with pytest.raises(DomainValidationError):
        normalize_cloud_account("aw$s:123")


def _snapshot(**overrides: object) -> ScopeSnapshot:
    base: dict[str, object] = {
        "id": "snap",
        "project_id": "proj",
        "include": ("example.com",),
        "exclude": (),
        "ports": (443,),
        "limits": ScopeLimits(requests_per_second=5.0, concurrency=3, max_requests=1000),
        "approved_by": "analyst",
        "approved_at": datetime(2026, 1, 1, tzinfo=UTC),
        "digest": "sha256:" + "0" * 64,
    }
    base.update(overrides)
    return ScopeSnapshot(**base)  # type: ignore[arg-type]


def test_scope_snapshot_cloud_accounts_default_empty() -> None:
    # Backward compatibility: a snapshot built without cloud_accounts works.
    snapshot = _snapshot()
    assert snapshot.cloud_accounts == ()
    assert not snapshot.includes_cloud_account("aws:123456789012")


def test_scope_snapshot_includes_cloud_account() -> None:
    snapshot = _snapshot(cloud_accounts=("aws:123456789012",))
    assert snapshot.includes_cloud_account("aws:123456789012")
    assert not snapshot.includes_cloud_account("aws:999999999999")


def test_scope_snapshot_cloud_account_normalizes_on_match() -> None:
    snapshot = _snapshot(cloud_accounts=("aws:123456789012",))
    # Provider casing / whitespace on the query side must not matter.
    assert snapshot.includes_cloud_account("AWS:123456789012")
    assert snapshot.includes_cloud_account("  aws:123456789012  ")


def test_scope_snapshot_cloud_account_deny_priority() -> None:
    # An account present in BOTH include and exclude is DENIED (Deny优先).
    snapshot = _snapshot(
        cloud_accounts=("aws:123456789012",),
        exclude=("aws:123456789012",),
    )
    assert not snapshot.includes_cloud_account("aws:123456789012")


def test_scope_freeze_normalizes_cloud_accounts_into_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Freeze time so the ONLY difference between the two snapshots is the
    # cloud_accounts field - proving it participates in the canonical digest.
    fixed = datetime(2026, 1, 1, tzinfo=UTC)
    monkeypatch.setattr("secopent.domain.scope.models.utc_now", lambda: fixed)

    draft_a = ScopeDraft(
        project_id="p",
        include=("https://example.test",),
        cloud_accounts=("AWS:123456789012",),
    )
    snap_a = draft_a.freeze(snapshot_id="s", approved_by="u")
    # Provider normalized to lowercase on freeze.
    assert snap_a.cloud_accounts == ("aws:123456789012",)
    assert snap_a.includes_cloud_account("aws:123456789012")

    # A draft differing ONLY in cloud_accounts must produce a different digest.
    draft_b = ScopeDraft(project_id="p", include=("https://example.test",))
    snap_b = draft_b.freeze(snapshot_id="s", approved_by="u")
    assert snap_a.digest != snap_b.digest


def test_scope_freeze_cloud_accounts_sorted_and_deduped() -> None:
    draft = ScopeDraft(
        project_id="p",
        include=("https://example.test",),
        cloud_accounts=("gcp:proj-b", "aws:111", "aws:111"),
    )
    snapshot = draft.freeze(snapshot_id="s", approved_by="u")
    assert snapshot.cloud_accounts == ("aws:111", "gcp:proj-b")
