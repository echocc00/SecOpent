"""ExecutionPermit expiry invariant + is_expired helper (W3-D T2)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from secopent.domain.common.errors import DomainValidationError
from secopent.domain.permits.models import DEFAULT_PERMIT_TTL_SECONDS, ExecutionPermit


def _permit(issued_at: datetime, expires_at: datetime) -> ExecutionPermit:
    return ExecutionPermit(
        job_id="j-1",
        worker_id="w-1",
        scope_digest="sha256:s",
        plan_digest="sha256:p",
        capabilities=(),
        budget=0.0,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce="n-1",
    )


def test_is_expired_false_before_expiry() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    permit = _permit(now, now + timedelta(seconds=DEFAULT_PERMIT_TTL_SECONDS))
    assert permit.is_expired(now) is False


def test_is_expired_true_at_or_after_expiry() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    expiry = now + timedelta(seconds=60)
    permit = _permit(now, expiry)
    assert permit.is_expired(expiry) is True
    assert permit.is_expired(expiry + timedelta(seconds=1)) is True


def test_expires_at_must_be_after_issued_at() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    with pytest.raises(DomainValidationError):
        _permit(now, now)  # equal -> invalid
    with pytest.raises(DomainValidationError):
        _permit(now, now - timedelta(seconds=1))  # before -> invalid
