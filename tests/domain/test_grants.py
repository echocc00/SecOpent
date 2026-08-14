"""EngagementGrant domain tests (v0.6.0, spec §3.1).

A grant is a human-granted authorization boundary: an embedded ScopeSnapshot
(one matcher - ScopeSnapshot owns target matching), risk caps, validity window.
covers_scope must be precise: every assessment target must match the grant's
scope; covers_risks caps every plan step.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from secopent.domain.common.errors import DomainValidationError
from secopent.domain.grants.models import EngagementGrant, GrantStatus
from secopent.domain.policy.models import RiskClass
from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot

_NOW = datetime(2026, 8, 8, tzinfo=UTC)


def _snap(
    *include: str, ports: tuple[int, ...] = (443,), snap_id: str = "snap"
) -> ScopeSnapshot:
    """A ScopeSnapshot whose include/ports mirror what assessments use."""
    return ScopeSnapshot(
        id=snap_id,
        project_id="proj-1",
        include=include,
        exclude=(),
        ports=ports,
        limits=ScopeLimits(5.0, 3, 50_000),
        approved_by="human",
        approved_at=_NOW,
        digest=f"sha256:{snap_id}",
    )


def _grant(**overrides: object) -> EngagementGrant:
    base = dict(
        id="grant-1",
        project_id="proj-1",
        name="ECS prod scan",
        scope=_snap("http://8.133.200.235/", "internal.example.com",
                    ports=(80, 443), snap_id="grant-scope"),
        risk_caps=frozenset({RiskClass.PASSIVE, RiskClass.LOW, RiskClass.ACTIVE}),
        valid_from=_NOW - timedelta(days=1),
        valid_to=_NOW + timedelta(days=7),
        created_by="operator-1",
        created_at=_NOW,
        status=GrantStatus.ACTIVE,
        digest="sha256:grant",
    )
    base.update(overrides)
    return EngagementGrant(**base)  # type: ignore[arg-type]


def test_create_rejects_destructive_risk_cap() -> None:
    with pytest.raises(DomainValidationError):
        EngagementGrant.create(
            project_id="proj-1", name="g", scope=_snap("http://8.133.200.235/"),
            risk_caps=frozenset({RiskClass.DESTRUCTIVE}),
            valid_from=_NOW, valid_to=_NOW + timedelta(days=1),
            created_by="operator-1", created_at=_NOW,
        )


def test_create_rejects_empty_name() -> None:
    with pytest.raises(DomainValidationError):
        EngagementGrant.create(
            project_id="proj-1", name="  ", scope=_snap("http://8.133.200.235/"),
            risk_caps=frozenset({RiskClass.LOW}),
            valid_from=_NOW, valid_to=_NOW + timedelta(days=1),
            created_by="operator-1", created_at=_NOW,
        )


def test_create_rejects_inverted_window() -> None:
    with pytest.raises(DomainValidationError):
        EngagementGrant.create(
            project_id="proj-1", name="g", scope=_snap("http://8.133.200.235/"),
            risk_caps=frozenset({RiskClass.LOW}),
            valid_from=_NOW + timedelta(days=1), valid_to=_NOW,
            created_by="operator-1", created_at=_NOW,
        )


def test_create_assigns_deterministic_digest_that_excludes_id() -> None:
    a = EngagementGrant.create(
        project_id="proj-1", name="g", scope=_snap("http://8.133.200.235/"),
        risk_caps=frozenset({RiskClass.LOW}),
        valid_from=_NOW, valid_to=_NOW + timedelta(days=1),
        created_by="operator-1", created_at=_NOW,
    )
    b = EngagementGrant.create(
        project_id="proj-1", name="g", scope=_snap("http://8.133.200.235/"),
        risk_caps=frozenset({RiskClass.LOW}),
        valid_from=_NOW, valid_to=_NOW + timedelta(days=1),
        created_by="operator-1", created_at=_NOW,
    )
    assert a.id != b.id  # uuid differs
    assert a.digest == b.digest  # digest is content-only, id-independent
    assert a.digest.startswith("sha256:")


def test_is_active_within_window() -> None:
    assert _grant().is_active_at(_NOW) is True


def test_expired_after_valid_to() -> None:
    g = _grant(valid_to=_NOW - timedelta(days=1))
    assert g.is_active_at(_NOW) is False
    assert g.status is GrantStatus.ACTIVE  # 惰性:status 不变,判断靠窗口


def test_revoked_is_not_active() -> None:
    g = _grant().revoke()
    assert g.status is GrantStatus.REVOKED
    assert g.is_active_at(_NOW) is False


def test_covers_scope_exact_ip_target() -> None:
    assert _grant().covers_scope(_snap("http://8.133.200.235/"))


def test_covers_scope_domain_target() -> None:
    assert _grant().covers_scope(_snap("internal.example.com"))


def test_covers_scope_rejects_out_of_grant_ip() -> None:
    assert not _grant().covers_scope(_snap("http://8.133.200.236/"))


def test_covers_scope_requires_all_targets_in_grant() -> None:
    assert not _grant().covers_scope(
        _snap("http://8.133.200.235/", "http://evil.example/")
    )


def test_covers_scope_rejects_extra_ports() -> None:
    assert not _grant().covers_scope(
        _snap("http://8.133.200.235/", ports=(443, 8443))
    )


def test_covers_scope_large_cidr_does_not_imply_subnet_scan() -> None:
    # 授权 /24 不等于能扫 /8:assessment 的每个 target 必须单独命中.
    wide = _grant(scope=_snap("10.0.0.0/24", ports=(80,), snap_id="wide"))
    assert wide.covers_scope(_snap("10.0.0.5", ports=(80,)))
    assert not wide.covers_scope(_snap("10.0.1.5", ports=(80,)))


def test_covers_risks_within_caps() -> None:
    from secopent.domain.assessments.models import PlanStep

    steps = (
        PlanStep(
            key="wstg-info-01", runner="nuclei", risk=RiskClass.LOW,
            parameters={}, dependencies=(),
        ),
    )
    assert _grant().covers_risks(steps)


def test_covers_risks_rejects_above_caps() -> None:
    from secopent.domain.assessments.models import PlanStep

    steps = (
        PlanStep(
            key="intrusive-01", runner="nuclei", risk=RiskClass.INTRUSIVE,
            parameters={}, dependencies=(),
        ),
    )
    assert not _grant().covers_risks(steps)