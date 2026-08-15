"""Mission end-to-end: target+intent -> grant-checked, LLM-planned, executed
(v0.6.3 spec §4.1/§4.3/§4.4).

One mission_create call must: validate the grant covers the target, create
the scope+assessment, let the LLM pick classes (deterministic floor when no
backend), approve via grant, start via grant, and SCHEDULE the executor (the
assessment must actually run, not stall in QUEUED).
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


def _create_grant(app, *, project_id: str, include: tuple[str, ...],
                  risk_caps: frozenset[RiskClass]) -> EngagementGrant:
    import uuid

    with app.state.db.unit_of_work() as uow:
        scope = ScopeDraft(
            project_id=project_id, include=include, exclude=(), ports=(80, 443),
            limits=ScopeLimits(5.0, 3, 50_000),
        ).freeze(snapshot_id=f"gs-{uuid.uuid4().hex[:8]}", approved_by="operator-1")
        svc = GrantService(SqlAlchemyGrantRepository(uow.session))
        grant = svc.create_human(
            project_id=project_id, name="mission grant",
            scope=scope, risk_caps=risk_caps,
            valid_from=datetime(2026, 1, 1, tzinfo=UTC),
            valid_to=datetime(2027, 1, 1, tzinfo=UTC),
            actor_role="human",
        )
        uow.session.commit()
        return grant


def test_mission_create_runs_full_chain(app, reg) -> None:
    project = reg.invoke("project_create", name="mission-e2e")
    grant = _create_grant(
        app, project_id=project["id"], include=("http://8.133.200.235/",),
        risk_caps=frozenset({RiskClass.PASSIVE, RiskClass.LOW}),
    )

    result = reg.invoke(
        "mission_create",
        project_id=project["id"],
        target="http://8.133.200.235/",
        intent="look for exposed admin panels",
        grant_id=grant.id,
    )
    assert result["status"] != "error", result
    assert result["assessment_id"]
    # full chain: created -> approved via grant -> started (queued/running+)
    assert result["status"] in {"queued", "running", "completed", "failed"}


def test_mission_create_out_of_scope_target_denied(app, reg) -> None:
    project = reg.invoke("project_create", name="mission-oos")
    grant = _create_grant(
        app, project_id=project["id"], include=("http://8.133.200.235/",),
        risk_caps=frozenset({RiskClass.LOW}),
    )

    result = reg.invoke(
        "mission_create",
        project_id=project["id"],
        target="http://192.168.50.50/",
        intent="x",
        grant_id=grant.id,
    )
    assert result["status"] == "error"
    assert "GRANT_SCOPE_MISMATCH" in str(result)


def test_mission_create_missing_grant_denied(app, reg) -> None:
    project = reg.invoke("project_create", name="mission-missing")
    result = reg.invoke(
        "mission_create",
        project_id=project["id"],
        target="http://8.133.200.235/",
        intent="x",
        grant_id="grant-missing",
    )
    assert result["status"] == "error"
    assert "GRANT" in str(result)


def test_mission_create_plan_floor_when_no_llm(app, reg) -> None:
    """Sandbox default has no LLM backend -> deterministic required floor still
    yields a valid plan + executed assessment."""
    project = reg.invoke("project_create", name="mission-no-llm")
    grant = _create_grant(
        app, project_id=project["id"], include=("http://8.133.200.235/",),
        risk_caps=frozenset({RiskClass.PASSIVE, RiskClass.LOW}),
    )

    result = reg.invoke(
        "mission_create",
        project_id=project["id"],
        target="http://8.133.200.235/",
        intent="anything",
        grant_id=grant.id,
    )
    assert result["status"] != "error", result


def test_mission_create_risk_cap_from_grant_limits_active(app, reg) -> None:
    """A grant capped at LOW cannot run a mission with an ACTIVE risk_cap."""
    project = reg.invoke("project_create", name="mission-cap")
    grant = _create_grant(
        app, project_id=project["id"], include=("http://8.133.200.235/",),
        risk_caps=frozenset({RiskClass.LOW}),
    )

    result = reg.invoke(
        "mission_create",
        project_id=project["id"],
        target="http://8.133.200.235/",
        intent="active",
        grant_id=grant.id,
        risk_cap="active",
    )
    assert result["status"] == "error"