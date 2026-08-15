"""AssessmentService approve/start via grant (v0.6.0 spec §3.4).

The grant path must override _require_human ONLY when the grant authorizes
the exact scope + plan; all existing human behavior must remain intact.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from secopent.application.assessments import (
    AssessmentPermissionError,
    AssessmentService,
)
from secopent.application.grants import GrantService
from secopent.domain.assessments.models import AssessmentStatus, PlanStep
from secopent.domain.grants.models import EngagementGrant
from secopent.domain.policy.models import RiskClass
from secopent.domain.projects.models import Project
from secopent.domain.scope.models import ScopeDraft, ScopeLimits, ScopeSnapshot

_NOW = datetime(2026, 8, 8, tzinfo=UTC)
# WIDE window: authorize(now=utc_now()) runs with the REAL clock; grants must
# stay active regardless of when the suite runs.
_FAR_FUTURE = datetime(2099, 1, 1, tzinfo=UTC)


@dataclass
class _MemoryGrantRepo:
    items: dict[str, EngagementGrant] = field(default_factory=dict)

    def add(self, g: EngagementGrant) -> None:
        self.items[g.id] = g

    def get(self, gid: str) -> EngagementGrant | None:
        return self.items.get(gid)

    def list_for_project(self, pid: str) -> tuple[EngagementGrant, ...]:
        return tuple(g for g in self.items.values() if g.project_id == pid)


def _grant_boundary(*include: str, ports: tuple[int, ...] = (80,)) -> ScopeSnapshot:
    """The grant's authorization boundary - must cover seeded assessments."""
    return ScopeDraft(
        project_id="p1", include=include, exclude=(), ports=list(ports),
        limits=ScopeLimits(10, 2, 100),
    ).freeze(snapshot_id="grant-scope", approved_by="operator-1")


def _grant(repo: _MemoryGrantRepo) -> EngagementGrant:
    g = EngagementGrant.create(
        project_id="p1", name="g", scope=_grant_boundary("http://target"),
        risk_caps=frozenset({RiskClass.LOW}),
        valid_from=_NOW, valid_to=_FAR_FUTURE,
        created_by="operator-1", created_at=_NOW,
    )
    repo.add(g)
    return g


def _seed_assessment(repos, *, include: tuple[str, ...] = ("http://target",)) -> str:
    """Project + scope + DRAFT assessment + plan + AWAITING_APPROVAL."""
    from secopent.domain.policy.models import ExecutionMode

    repos.projects.add(Project.create(project_id="p1", name="t"))
    repos.scopes.add_snapshot(ScopeSnapshot(
        id="s1", project_id="p1", include=include, exclude=(),
        ports=(80,),
        limits=ScopeLimits(10, 2, 100),
        approved_by="a", approved_at=_NOW, digest="sha256:scope",
    ))
    svc = AssessmentService(repos.assessments)
    a = svc.create(project_id="p1", scope_snapshot_id="s1",
                   mode=ExecutionMode.APPROVAL)
    svc.attach_plan(a.id, steps=(
        PlanStep(key="k", runner="nuclei", risk=RiskClass.LOW,
                 parameters={}, dependencies=()),
    ))
    return a.id


def _svc(repos, grant_repo: _MemoryGrantRepo | None = None) -> AssessmentService:
    # The real in-memory scope repo (repos.scopes) IS the assessment's scope
    # store - the same object the seed wrote into. AssessmentService's
    # scope_repo must resolve the assessment's scope_snapshot_id, so pass the
    # repo that owns it.
    return AssessmentService(
        repos.assessments,
        scope_repo=repos.scopes,  # type: ignore[arg-type]
        grant_service=GrantService(grant_repo or _MemoryGrantRepo()),
    )


def test_agent_approve_via_grant_records_grant_approver(memory_repositories) -> None:
    grant_repo = _MemoryGrantRepo()
    grant = _grant(grant_repo)
    svc = _svc(memory_repositories, grant_repo)
    aid = _seed_assessment(memory_repositories)

    approval = svc.approve(
        assessment_id=aid,
        approved_by="agent",  # overridden -> grant:
        approved_risks=frozenset({RiskClass.LOW}),
        approved_capabilities=frozenset(),
        scope_digest="sha256:scope",
        actor_role="agent",
        grant_id=grant.id,
    )
    assert approval.approved_by == f"grant:{grant.id}"
    assert memory_repositories.assessments.get(aid).status is AssessmentStatus.APPROVED


def test_agent_start_via_grant_queues(memory_repositories) -> None:
    grant_repo = _MemoryGrantRepo()
    grant = _grant(grant_repo)
    svc = _svc(memory_repositories, grant_repo)
    aid = _seed_assessment(memory_repositories)
    svc.approve(assessment_id=aid, approved_by="agent",
                approved_risks=frozenset({RiskClass.LOW}),
                approved_capabilities=frozenset(), scope_digest="sha256:scope",
                actor_role="agent", grant_id=grant.id)

    started = svc.start(aid, actor_role="agent", grant_id=grant.id)
    assert started.status is AssessmentStatus.QUEUED


def test_agent_without_grant_still_denied_on_start(memory_repositories) -> None:
    grant_repo = _MemoryGrantRepo()
    _grant(grant_repo)
    svc = _svc(memory_repositories, grant_repo)
    aid = _seed_assessment(memory_repositories)
    svc.approve(assessment_id=aid, approved_by="human",
                approved_risks=frozenset({RiskClass.LOW}),
                approved_capabilities=frozenset(), scope_digest="sha256:scope",
                actor_role="human")

    with pytest.raises(AssessmentPermissionError):
        svc.start(aid, actor_role="agent")  # no grant_id -> human-only


def test_agent_approve_scope_mismatch_denied(memory_repositories) -> None:
    grant_repo = _MemoryGrantRepo()
    grant = _grant(grant_repo)  # boundary covers http://target
    svc = _svc(memory_repositories, grant_repo)
    # seed an assessment whose scope is NOT covered by the grant
    aid = _seed_assessment(
        memory_repositories, include=("http://8.133.200.236/",)
    )

    with pytest.raises(AssessmentPermissionError) as excinfo:
        svc.approve(assessment_id=aid, approved_by="agent",
                    approved_risks=frozenset({RiskClass.LOW}),
                    approved_capabilities=frozenset(), scope_digest="sha256:scope",
                    actor_role="agent", grant_id=grant.id)
    assert "grant denied: GRANT_SCOPE_MISMATCH" in str(excinfo.value)


def test_agent_approve_expired_grant_denied(memory_repositories) -> None:
    grant_repo = _MemoryGrantRepo()
    expired = EngagementGrant.create(
        project_id="p1", name="expired", scope=_grant_boundary("http://target"),
        risk_caps=frozenset({RiskClass.LOW}),
        valid_from=_NOW - timedelta(days=2), valid_to=_NOW - timedelta(days=1),
        created_by="operator-1", created_at=_NOW,
    )
    grant_repo.add(expired)
    svc = _svc(memory_repositories, grant_repo)
    aid = _seed_assessment(memory_repositories)

    with pytest.raises(AssessmentPermissionError) as excinfo:
        svc.approve(assessment_id=aid, approved_by="agent",
                    approved_risks=frozenset({RiskClass.LOW}),
                    approved_capabilities=frozenset(), scope_digest="sha256:scope",
                    actor_role="agent", grant_id=expired.id)
    assert "grant denied: GRANT_INACTIVE" in str(excinfo.value)


def test_grant_id_without_grant_service_denied(memory_repositories) -> None:
    """degrades safe: a grant_id passed to a service with no grant service."""
    svc = AssessmentService(memory_repositories.assessments)
    aid = _seed_assessment(memory_repositories)

    with pytest.raises(AssessmentPermissionError):
        svc.approve(assessment_id=aid, approved_by="agent",
                    approved_risks=frozenset({RiskClass.LOW}),
                    approved_capabilities=frozenset(), scope_digest="sha256:scope",
                    actor_role="agent", grant_id="g")