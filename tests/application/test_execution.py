# tests/application/test_execution.py
"""P0 execution layer wiring tests (v0.1.2).

Covers: AssessmentService.start/mark_running/complete/fail state transitions +
actor_role boundary, and execute_assessment end-to-end with a fake step runner
(no Docker) proving findings are correlated + persisted with assessment_id.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from secopent.application.assessments import (
    AssessmentPermissionError,
    AssessmentService,
)
from secopent.application.orchestrator import StepResult
from secopent.domain.adapters.contracts import (
    AdapterSource,
    CoverageDomain,
    Observation,
    Severity,
)
from secopent.domain.assessments.models import (
    Assessment,
    AssessmentStatus,
    PlanStep,
)
from secopent.domain.findings.models import Finding
from secopent.domain.policy.models import ExecutionMode, RiskClass
from secopent.domain.projects.models import Project
from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot


@dataclass
class _MemoryFindingRepo:
    items: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.items.append(finding)


@dataclass
class _FakeStepRunner:
    """Returns canned observations per step; satisfies the StepRunner contract."""
    observations: tuple[Observation, ...]
    _all: list[Observation] = field(default_factory=list)

    def run(self, step: PlanStep) -> StepResult:
        self._all.extend(self.observations)
        return StepResult(result_digest="sha256:fake")

    def all_observations(self) -> tuple[Observation, ...]:
        return tuple(self._all)


def _seed_approved(repos) -> Assessment:
    """Build a project -> scope -> assessment -> plan -> approval (APPROVED)."""
    repos.projects.add(Project.create(project_id="p1", name="t"))
    repos.scopes.add_snapshot(ScopeSnapshot(
        id="s1", project_id="p1", include=("http://target",), exclude=(),
        ports=(80,), limits=ScopeLimits(requests_per_second=10, concurrency=2, max_requests=100),
        approved_by="a", approved_at=datetime.now(UTC), digest="sha256:scope",
    ))
    service = AssessmentService(repos.assessments)
    assessment = service.create(
        project_id="p1", scope_snapshot_id="s1", mode=ExecutionMode.APPROVAL
    )
    step = PlanStep(
        key="nuclei-sqli", runner="nuclei", risk=RiskClass.LOW,
        parameters={"target": "http://target"}, dependencies=(),
    )
    service.attach_plan(assessment.id, steps=(step,))
    service.approve(
        assessment_id=assessment.id, approved_by="analyst",
        approved_risks=frozenset({RiskClass.LOW}),
        approved_capabilities=frozenset(), scope_digest="sha256:scope",
    )
    return repos.assessments.get(assessment.id)


def _observation() -> Observation:
    return Observation(
        external_id="o1", asset_identity="http://target",
        source=AdapterSource(name="nuclei", version="1", template_version="1"),
        rule_id="sqli", rule_version="1", coverage_domain=CoverageDomain.WEB,
        title="SQL Injection", severity=Severity.HIGH, confidence=0.9,
    )


# --- AssessmentService state transitions ------------------------------------


def test_start_moves_approved_to_queued(memory_repositories):
    a = _seed_approved(memory_repositories)
    result = AssessmentService(memory_repositories.assessments).start(a.id)
    assert result.status is AssessmentStatus.QUEUED


def test_start_rejects_agent(memory_repositories):
    a = _seed_approved(memory_repositories)
    with pytest.raises(AssessmentPermissionError):
        AssessmentService(memory_repositories.assessments).start(a.id, actor_role="agent")


def test_start_rejects_non_approved(memory_repositories):
    service = AssessmentService(memory_repositories.assessments)
    a = service.create(project_id="p", scope_snapshot_id="s", mode=ExecutionMode.APPROVAL)
    from secopent.domain.common.errors import DomainValidationError
    with pytest.raises(DomainValidationError):
        service.start(a.id)


def test_mark_running_complete_fail_transitions(memory_repositories):
    a = _seed_approved(memory_repositories)
    service = AssessmentService(memory_repositories.assessments)
    assert service.start(a.id).status is AssessmentStatus.QUEUED
    assert service.mark_running(a.id).status is AssessmentStatus.RUNNING
    assert service.complete(a.id).status is AssessmentStatus.COMPLETED


def test_fail_records_failed_status(memory_repositories):
    a = _seed_approved(memory_repositories)
    service = AssessmentService(memory_repositories.assessments)
    service.start(a.id)
    service.mark_running(a.id)
    assert service.fail(a.id, "adapter crashed").status is AssessmentStatus.FAILED


# --- execute_assessment end-to-end (no Docker) ------------------------------


def test_execute_assessment_correlates_findings_and_completes(memory_repositories):
    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)  # -> QUEUED
    finding_repo = _MemoryFindingRepo()

    from secopent.application.execution import execute_assessment

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=finding_repo,
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
    )

    assert memory_repositories.assessments.get(a.id).status is AssessmentStatus.COMPLETED
    assert len(finding_repo.items) == 1
    assert finding_repo.items[0].assessment_id == a.id
    actions = [e.action for e in memory_repositories.audit.events]
    assert "assessment.started" in actions and "assessment.completed" in actions


def test_execute_assessment_records_failed_on_exception(memory_repositories):
    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)

    def _boom(_scope):  # noqa: ANN001
        raise RuntimeError("adapter exploded")

    from secopent.application.execution import execute_assessment

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=_boom,
    )
    assert memory_repositories.assessments.get(a.id).status is AssessmentStatus.FAILED
    assert any(e.action == "assessment.failed" for e in memory_repositories.audit.events)
