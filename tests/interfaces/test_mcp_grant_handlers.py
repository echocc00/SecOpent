"""MCP grant handlers: plan_approve/start via grant + grant_list (v0.6.0 §3.5).

End-to-end through the framework-free registry with a real create_app runtime:
- no grant_id -> structured HUMAN_REQUIRED (unchanged for the agent)
- valid grant  -> approve/start really happen, recorded as grant:<id>
- start via grant actually schedules the executor (v0.4.0 QUEUED-stall shape
  must not recur)
- grant_list returns only ACTIVE grants, never the lifecycle machinery
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from secopent.application.grants import GrantService
from secopent.domain.grants.models import EngagementGrant
from secopent.domain.policy.models import RiskClass
from secopent.domain.scope.models import ScopeDraft, ScopeLimits
from secopent.infrastructure.repositories.sqlalchemy_grants import (
    SqlAlchemyGrantRepository,
)


@pytest.fixture
def app():
    from secopent.interfaces.api.main import create_app

    return create_app()


@pytest.fixture
def reg(app):
    return app.state.mcp_tool_registry


def _create_grant(app, *, project_id: str, include: tuple[str, ...]) -> EngagementGrant:
    """Human-path grant creation via the real repo (actor_role="human").

    Note: SqlAlchemyGrantRepository.add persists the embedded scope itself
    (into core_scope_snapshots), so we must NOT add_snapshot it here first.
    """
    import uuid

    with app.state.db.unit_of_work() as uow:
        scope = ScopeDraft(
            project_id=project_id, include=include, exclude=(), ports=(80, 443),
            limits=ScopeLimits(5.0, 3, 50_000),
        ).freeze(snapshot_id=f"gs-{uuid.uuid4().hex[:8]}", approved_by="operator-1")
        svc = GrantService(SqlAlchemyGrantRepository(uow.session))
        grant = svc.create_human(
            project_id=project_id, name="rogue grant",
            scope=scope,
            risk_caps=frozenset({RiskClass.PASSIVE, RiskClass.LOW, RiskClass.ACTIVE}),
            valid_from=datetime(2026, 1, 1, tzinfo=UTC),
            valid_to=datetime(2027, 1, 1, tzinfo=UTC),
            actor_role="human",
        )
        uow.session.commit()
        return grant


def _seed_approved_assessment(reg, *, include: str = "http://8.133.200.235/") -> dict:
    """project -> scope -> assessment_create -> plan_generate (AWAITING_APPROVAL)."""
    project = reg.invoke("project_create", name="grant-e2e")
    scope = reg.invoke(
        "scope_freeze",
        project_id=project["id"],
        include=[include],
        approved_by="operator-1",
    )
    created = reg.invoke(
        "assessment_create",
        project_id=project["id"],
        scope_snapshot_id=scope["id"],
    )
    reg.invoke("plan_generate", assessment_id=created["id"])
    return {"project": project, "scope": scope, "assessment": created}


def test_plan_approve_without_grant_is_human_required(app, reg) -> None:
    seeded = _seed_approved_assessment(reg)
    result = reg.invoke("plan_approve", assessment_id=seeded["assessment"]["id"])
    assert result["status"] == "HUMAN_REQUIRED"
    assert result["action"] == "plan_approve"


def test_assessment_start_without_grant_is_human_required(app, reg) -> None:
    seeded = _seed_approved_assessment(reg)
    result = reg.invoke("assessment_start", assessment_id=seeded["assessment"]["id"])
    assert result["status"] == "HUMAN_REQUIRED"
    assert result["action"] == "assessment_start"


def _mk_grant(app, project_id):
    return _create_grant(app, project_id=project_id,
                         include=("http://8.133.200.235/",))


def test_plan_approve_with_matching_grant_succeeds(app, reg) -> None:
    seeded = _seed_approved_assessment(reg)
    grant = _mk_grant(app, seeded["project"]["id"])

    result = reg.invoke(
        "plan_approve", assessment_id=seeded["assessment"]["id"], grant_id=grant.id
    )
    # handler returns the refreshed assessment (success) vs structured error
    assert result["status"] == "approved"

    status = reg.invoke("assessment_status", assessment_id=seeded["assessment"]["id"])
    assert status["status"] == "approved"


def test_start_with_matching_grant_runs_to_queued(app, reg) -> None:
    seeded = _seed_approved_assessment(reg)
    grant = _mk_grant(app, seeded["project"]["id"])
    reg.invoke("plan_approve", assessment_id=seeded["assessment"]["id"],
               grant_id=grant.id)

    result = reg.invoke("assessment_start", assessment_id=seeded["assessment"]["id"],
                        grant_id=grant.id)
    assert result["status"] == "queued"


def test_start_with_scope_mismatch_grant_denied(app, reg) -> None:
    # grant covers 8.133.200.235; assessment targets 8.133.200.236
    seeded = _seed_approved_assessment(reg, include="http://8.133.200.236/")
    grant = _create_grant(app, project_id=seeded["project"]["id"],
                          include=("http://8.133.200.235/",))

    result = reg.invoke(
        "plan_approve", assessment_id=seeded["assessment"]["id"], grant_id=grant.id
    )
    assert result["status"] != "success"
    assert "GRANT_SCOPE_MISMATCH" in str(result)


def test_grant_list_returns_active_only(app, reg) -> None:
    project = reg.invoke("project_create", name="grant-list")
    grant = _create_grant(app, project_id=project["id"],
                          include=("http://8.133.200.235/",))
    # revoke it -> should vanish from list_active
    with app.state.db.unit_of_work() as uow:
        GrantService(SqlAlchemyGrantRepository(uow.session)).revoke(
            grant.id, actor_role="human"
        )
        uow.session.commit()

    result = reg.invoke("grant_list", project_id=project["id"])
    assert result["status"] == "success"
    assert result["grants"] == []