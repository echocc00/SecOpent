"""GrantService: create_human / revoke / authorize (v0.6.0 spec §3.3)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from secopent.application.assessments import AssessmentPermissionError
from secopent.application.grants import GrantService
from secopent.domain.assessments.models import PlanStep
from secopent.domain.grants.models import EngagementGrant, GrantStatus
from secopent.domain.policy.models import RiskClass
from secopent.domain.scope.models import ScopeDraft, ScopeLimits, ScopeSnapshot

_NOW = datetime(2026, 8, 8, tzinfo=UTC)


@dataclass
class _MemoryGrantRepo:
    items: dict[str, EngagementGrant] = field(default_factory=dict)

    def add(self, grant: EngagementGrant) -> None:
        self.items[grant.id] = grant

    def get(self, grant_id: str) -> EngagementGrant | None:
        return self.items.get(grant_id)

    def list_for_project(self, project_id: str) -> tuple[EngagementGrant, ...]:
        return tuple(
            g for g in self.items.values() if g.project_id == project_id
        )


def _scope(*include: str, snap_id: str = "s1", ports: tuple[int, ...] = (80, 443)) -> ScopeSnapshot:
    return ScopeDraft(
        project_id="proj-1",
        include=include,
        exclude=(),
        ports=list(ports),
        limits=ScopeLimits(5.0, 3, 50_000),
    ).freeze(snapshot_id=snap_id, approved_by="operator-1")


def _step(risk: RiskClass) -> PlanStep:
    return PlanStep(
        key=f"step-{risk.value}", runner="nuclei", risk=risk,
        parameters={}, dependencies=(),
    )


def _service(repo: _MemoryGrantRepo | None = None) -> GrantService:
    return GrantService(repo or _MemoryGrantRepo())


def test_create_human_by_agent_raises_and_writes_nothing() -> None:
    repo = _MemoryGrantRepo()
    with pytest.raises(AssessmentPermissionError):
        _service(repo).create_human(
            project_id="proj-1", name="g", scope=_scope("http://8.133.200.235/"),
            risk_caps=frozenset({RiskClass.LOW}),
            valid_from=_NOW, valid_to=_NOW + timedelta(days=1),
            actor_role="agent",
        )
    assert repo.items == {}


def test_create_human_by_human_ok() -> None:
    g = _service().create_human(
        project_id="proj-1", name="g", scope=_scope("http://8.133.200.235/"),
        risk_caps=frozenset({RiskClass.LOW}),
        valid_from=_NOW, valid_to=_NOW + timedelta(days=1),
        actor_role="human",
    )
    assert g.status is GrantStatus.ACTIVE
    assert g.digest.startswith("sha256:")


def test_authorize_active_and_covered() -> None:
    repo = _MemoryGrantRepo()
    svc = _service(repo)
    svc.create_human(
        project_id="proj-1", name="g", scope=_scope("http://8.133.200.235/"),
        risk_caps=frozenset({RiskClass.LOW}),
        valid_from=_NOW, valid_to=_NOW + timedelta(days=1), actor_role="human",
    )
    gid = next(iter(repo.items))
    decision = svc.authorize(
        gid, _scope("http://8.133.200.235/"), (_step(RiskClass.LOW),), now=_NOW
    )
    assert decision.allowed is True
    assert decision.reason == "ALLOWED"


def test_authorize_grant_not_found() -> None:
    decision = _service().authorize(
        "grant-missing", _scope("http://8.133.200.235/"), (), now=_NOW
    )
    assert decision.allowed is False
    assert decision.reason == "GRANT_NOT_FOUND"


def test_authorize_expired_grant() -> None:
    repo = _MemoryGrantRepo()
    svc = _service(repo)
    svc.create_human(
        project_id="proj-1", name="g", scope=_scope("http://8.133.200.235/"),
        risk_caps=frozenset({RiskClass.LOW}),
        valid_from=_NOW - timedelta(days=2), valid_to=_NOW - timedelta(days=1),
        actor_role="human",
    )
    gid = next(iter(repo.items))
    decision = svc.authorize(gid, _scope("http://8.133.200.235/"), (), now=_NOW)
    assert decision.allowed is False
    assert decision.reason == "GRANT_INACTIVE"


def test_authorize_scope_mismatch() -> None:
    repo = _MemoryGrantRepo()
    svc = _service(repo)
    svc.create_human(
        project_id="proj-1", name="g", scope=_scope("http://8.133.200.235/"),
        risk_caps=frozenset({RiskClass.LOW}),
        valid_from=_NOW, valid_to=_NOW + timedelta(days=1), actor_role="human",
    )
    gid = next(iter(repo.items))
    decision = svc.authorize(
        gid, _scope("http://8.133.200.236/", snap_id="other"), (), now=_NOW
    )
    assert decision.allowed is False
    assert decision.reason == "GRANT_SCOPE_MISMATCH"


def test_authorize_risk_exceeds_caps() -> None:
    repo = _MemoryGrantRepo()
    svc = _service(repo)
    svc.create_human(
        project_id="proj-1", name="g", scope=_scope("http://8.133.200.235/"),
        risk_caps=frozenset({RiskClass.LOW}),
        valid_from=_NOW, valid_to=_NOW + timedelta(days=1), actor_role="human",
    )
    gid = next(iter(repo.items))
    decision = svc.authorize(
        gid, _scope("http://8.133.200.235/"), (_step(RiskClass.ACTIVE),), now=_NOW
    )
    assert decision.allowed is False
    assert decision.reason == "GRANT_RISK_NOT_APPROVED"


def test_revoke_marks_status_and_blocks_authorize() -> None:
    repo = _MemoryGrantRepo()
    svc = _service(repo)
    g = svc.create_human(
        project_id="proj-1", name="g", scope=_scope("http://8.133.200.235/"),
        risk_caps=frozenset({RiskClass.LOW}),
        valid_from=_NOW, valid_to=_NOW + timedelta(days=1), actor_role="human",
    )
    assert svc.revoke(g.id, actor_role="human").status is GrantStatus.REVOKED
    assert (
        svc.authorize(g.id, _scope("http://8.133.200.235/"), (), now=_NOW).allowed
        is False
    )


def test_revoke_by_agent_denied() -> None:
    repo = _MemoryGrantRepo()
    svc = _service(repo)
    g = svc.create_human(
        project_id="proj-1", name="g", scope=_scope("http://8.133.200.235/"),
        risk_caps=frozenset({RiskClass.LOW}),
        valid_from=_NOW, valid_to=_NOW + timedelta(days=1), actor_role="human",
    )
    with pytest.raises(AssessmentPermissionError):
        svc.revoke(g.id, actor_role="agent")
    assert repo.items[g.id].status is GrantStatus.ACTIVE


def test_list_active_filters_expired_and_revoked() -> None:
    repo = _MemoryGrantRepo()
    svc = _service(repo)
    alive = svc.create_human(
        project_id="proj-1", name="alive", scope=_scope("http://8.133.200.235/", snap_id="a"),
        risk_caps=frozenset({RiskClass.LOW}),
        valid_from=_NOW, valid_to=_NOW + timedelta(days=7), actor_role="human",
    )
    stale = svc.create_human(
        project_id="proj-1", name="stale", scope=_scope("http://8.133.200.235/", snap_id="b"),
        risk_caps=frozenset({RiskClass.LOW}),
        valid_from=_NOW - timedelta(days=2), valid_to=_NOW - timedelta(days=1),
        actor_role="human",
    )
    active = svc.list_active("proj-1", now=_NOW)
    assert [g.id for g in active] == [alive.id]
    assert stale.id not in [g.id for g in active]