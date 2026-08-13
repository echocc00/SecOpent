"""Interfaces: MCP tool registry lifecycle + structured results (MCP §13).

End-to-end through the framework-free registry wired with a real
``create_app`` runtime (isolated tmp SQLite via tests/conftest.py):

- all 17 standard orchestration tools are registered (superset check);
- a full lifecycle project->scope->assessment->plan works through the tools;
- the human boundary returns structured HUMAN_REQUIRED (never a raw 403);
- pause/resume/cancel round-trip through the state machine;
- read-only tools (asset/finding/intel/report) return structured results.
"""
from __future__ import annotations

import pytest

from secopent.interfaces.api.main import create_app
from secopent.interfaces.mcp import STANDARD_ORCHESTRATION_TOOLS
from secopent.interfaces.mcp.tool_registry import McpToolRegistry

EXPECTED_16 = set(STANDARD_ORCHESTRATION_TOOLS)


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def reg(app):
    registry = app.state.mcp_tool_registry
    assert isinstance(registry, McpToolRegistry)
    return registry


def test_all_standard_tools_registered(reg) -> None:  # noqa: ANN001
    names = set(reg.names())
    missing = EXPECTED_16 - names
    assert not missing, f"standard tools not registered: {sorted(missing)}"
    assert len(reg.names()) >= 17


def test_no_registered_tool_has_dangerous_substring(reg) -> None:  # noqa: ANN001
    dangerous = ("shell", "docker", "python", "exec", "eval", "subprocess", "run_command")
    for name in reg.names():
        assert not any(s in name.lower() for s in dangerous), name


def test_full_lifecycle_with_human_boundary(app, reg) -> None:  # noqa: ANN001
    project = reg.invoke("project_create", name="lifecycle")
    assert project["id"].startswith("proj-")

    scope = reg.invoke(
        "scope_freeze",
        project_id=project["id"],
        include=["http://example.com"],
        approved_by="tester",
        ports=[443, 80],
        cloud_accounts=["AWS:123456789012"],
    )
    assert scope["id"].startswith("scope-")
    assert scope["cloud_accounts"] == ["aws:123456789012"]

    # The full agent chain now includes assessment_create (draft proposal).
    created = reg.invoke(
        "assessment_create",
        project_id=project["id"],
        scope_snapshot_id=scope["id"],
    )
    assert created["id"].startswith("asm-")
    assert created["status"] == "draft"
    assessment_id = created["id"]

    plan = reg.invoke("plan_generate", assessment_id=assessment_id)
    assert plan["steps"], "plan has steps"
    status = reg.invoke("assessment_status", assessment_id=assessment_id)
    assert status["status"] == "awaiting_approval"

    # The agent may never approve or start: HUMAN_REQUIRED, structured.
    approve = reg.invoke("plan_approve", assessment_id=assessment_id)
    assert approve["status"] == "HUMAN_REQUIRED"
    assert approve["action"] == "plan_approve"
    assert approve["assessment_id"] == assessment_id
    assert "human" in approve["next_step"].lower()

    start = reg.invoke("assessment_start", assessment_id=assessment_id)
    assert start["status"] == "HUMAN_REQUIRED"
    assert start["action"] == "assessment_start"


def test_pause_resume_cancel_round_trip(app, reg) -> None:  # noqa: ANN001
    from dataclasses import replace

    from secopent.application.assessments import AssessmentService
    from secopent.domain.assessments.models import AssessmentStatus
    from secopent.domain.policy.models import ExecutionMode
    from secopent.infrastructure.repositories.sqlalchemy_core import (
        SqlAlchemyAssessmentRepository,
    )

    def _drive_to_running() -> str:
        # Real project + scope rows (foreign keys are enforced).
        project = reg.invoke("project_create", name="pause-demo")
        scope = reg.invoke(
            "scope_freeze",
            project_id=project["id"],
            include=["http://example.com"],
            approved_by="tester",
        )
        with app.state.db.unit_of_work() as uow:
            repo = SqlAlchemyAssessmentRepository(uow.session)
            service = AssessmentService(repo)
            created = service.create(
                project_id=project["id"], scope_snapshot_id=scope["id"],
                mode=ExecutionMode.APPROVAL,
            )
            # Bypass approval just for the persistence-only state machine.
            repo.add(replace(created, status=AssessmentStatus.QUEUED))
            return service.mark_running(created.id).id  # noqa: SLF001

    aid = _drive_to_running()
    assert reg.invoke("assessment_pause", assessment_id=aid)["status"] == "paused"
    assert reg.invoke("assessment_resume", assessment_id=aid)["status"] == "running"
    assert reg.invoke("assessment_cancel", assessment_id=aid)["status"] == "cancelled"
    # Terminal: further moves are structured errors, not crashes.
    err = reg.invoke("assessment_pause", assessment_id=aid)
    assert err["status"] == "error"


def test_status_not_found_is_structured(reg) -> None:  # noqa: ANN001
    result = reg.invoke("assessment_status", assessment_id="nope")
    assert result["status"] == "error"
    assert result["code"] == "NOT_FOUND"


def test_scope_validate_reports_errors(reg) -> None:  # noqa: ANN001
    result = reg.invoke(
        "scope_validate",
        include=["http://example.com", ""],
        ports=[443, 99999],
    )
    assert result["status"] == "invalid"
    raws = [e["raw"] for e in result["errors"]]
    assert "" in raws and "99999" in raws


def test_read_only_tools_return_structured_results(reg) -> None:  # noqa: ANN001
    assert reg.invoke("asset_list") == {"nodes": [], "edges": []}
    findings = reg.invoke("finding_list")
    assert findings["findings"] == []
    assert reg.invoke("intel_search", keyword="sql")["results"] == []
    assert reg.invoke("finding_validate", finding_id="nope")["code"] == "NOT_FOUND"


def test_finding_validate_never_accepts_agent_verdict(reg, app) -> None:  # noqa: ANN001
    """finding_validate is read-only: it never sets an oracle verdict."""
    from secopent.domain.adapters.contracts import Severity
    from secopent.domain.common.canonical import canonical_digest
    from secopent.domain.findings.models import Finding, FindingStatus
    from secopent.infrastructure.repositories.sqlalchemy_findings import (
        SqlAlchemyFindingRepository,
    )

    with app.state.db.unit_of_work() as uow:
        repo = SqlAlchemyFindingRepository(uow.session)
        fingerprint = canonical_digest({"title": "demo", "asset": "a", "cwe": ()})
        finding = Finding(
            id=f"finding:{fingerprint[:16]}",
            fingerprint=fingerprint,
            title="demo", asset="a", severity=Severity.MEDIUM,
            status=FindingStatus.CANDIDATE,
        )
        repo.add(finding)
        finding_id = finding.id

    result = reg.invoke("finding_validate", finding_id=finding_id)
    assert result["status"] == "not_validated"
    assert result["validated"] is False
    # The verdict was NOT written by the agent call.
    with app.state.db.unit_of_work() as uow:
        persisted = SqlAlchemyFindingRepository(uow.session).get(finding_id)
        assert persisted is not None
        assert persisted.oracle_verdict.value == "pending"