"""Empty-execution invariant + nft hardening audit (v0.5.2, v8 issue).

An assessment whose every plan step failed (WORKER_UNAVAILABLE) and that
produced zero observations must be marked FAILED, never COMPLETED - otherwise
``coverage_rate=0.0 findings=0`` masquerades as "target is clean" when in fact
nothing was scanned (the v8 NAS incident: 9 nuclei steps all failed to launch,
the run still completed).

Also covers the nft egress-guard downgrade: when nft ``apply_scope`` fails, a
``egress.hardening_unavailable`` audit event must be recorded (the downgrade
must not be silent), while the scan itself continues.
"""
from __future__ import annotations

from test_execution import (  # type: ignore[import-not-found]
    _FakeStepRunner,
    _MemoryFindingRepo,
    _observation,
    _seed_approved,
)

from secopent.application.assessments import AssessmentService
from secopent.application.execution import execute_assessment
from secopent.application.orchestrator import StepFailure, StepResult
from secopent.domain.adapters.contracts import Observation
from secopent.domain.assessments.models import AssessmentStatus, PlanStep
from secopent.domain.jobs.models import FailureClass


class _FailingStepRunner:
    """Every step fails with WORKER_UNAVAILABLE -> zero observations."""

    def run(self, step: PlanStep) -> StepResult:
        raise StepFailure(FailureClass.WORKER_UNAVAILABLE, "container launch failed")

    def all_observations(self) -> tuple[Observation, ...]:
        return ()


class _ZeroOutputStepRunner:
    """Every step SUCCEEDS but produces zero observations (v8 scenario #3:
    the container ran and exited 0, but every probe/template failed - e.g.
    an ISP throttling 13.5k HTTPS probes)."""

    def run(self, step: PlanStep) -> StepResult:
        return StepResult(result_digest="sha256:empty")

    def all_observations(self) -> tuple[Observation, ...]:
        return ()


def test_zero_success_zero_findings_marks_assessment_failed(memory_repositories) -> None:
    """v8 §4.7: 0 steps succeeded + 0 findings -> FAILED, not COMPLETED."""
    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FailingStepRunner(),
    )

    assessment = memory_repositories.assessments.get(a.id)
    assert assessment is not None
    assert assessment.status is AssessmentStatus.FAILED
    actions = [e.action for e in memory_repositories.audit.events]
    assert "assessment.completed.empty_execution" in actions
    assert "assessment.completed" not in actions


def test_clean_scan_with_zero_findings_stays_completed(memory_repositories) -> None:
    """A scan that RAN but found nothing is COMPLETED (the invariant must not
    punish a genuinely clean target)."""
    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
    )

    assessment = memory_repositories.assessments.get(a.id)
    assert assessment is not None
    assert assessment.status is AssessmentStatus.COMPLETED
    actions = [e.action for e in memory_repositories.audit.events]
    assert "assessment.completed" in actions


def test_zero_observations_with_successful_steps_flags_no_observations(
    memory_repositories,
) -> None:
    """v8 scenario #3: steps SUCCEEDED but zero observations (container ran,
    exit 0, but every probe failed - e.g. ISP throttling 13.5k templates).

    This is genuinely ambiguous with a clean target (nuclei exits 0 either
    way), so it stays COMPLETED - but the completed audit payload MUST carry
    an explicit ``no_observations`` flag so the anomaly is visible without
    falsely failing a clean scan.
    """
    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _ZeroOutputStepRunner(),
    )

    assessment = memory_repositories.assessments.get(a.id)
    assert assessment is not None
    assert assessment.status is AssessmentStatus.COMPLETED  # not a false FAILED
    events = memory_repositories.audit.events
    completed = [e for e in events if e.action == "assessment.completed"]
    assert completed
    assert completed[-1].payload.get("no_observations") is True


def test_observations_present_no_no_observations_flag(memory_repositories) -> None:
    """A scan that produced observations must NOT carry the no_observations
    flag on its completed audit event."""
    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
    )

    events = memory_repositories.audit.events
    completed = [e for e in events if e.action == "assessment.completed"]
    assert completed
    assert completed[-1].payload.get("no_observations") is None


def test_nft_failure_records_hardening_unavailable_audit(memory_repositories) -> None:
    """v8 §3.1: nft apply_scope failure must be audited, not silent."""

    class _FailingNft:
        def apply_scope(self, snapshot: object, *, session=None) -> object:
            raise RuntimeError("nft binary missing")

        def revoke(self) -> None:
            pass

    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
        nft_scope_enforcer=_FailingNft(),
    )

    actions = [e.action for e in memory_repositories.audit.events]
    assert "egress.hardening_unavailable" in actions
    # The scan continues despite the nft downgrade.
    assert memory_repositories.assessments.get(a.id).status is AssessmentStatus.COMPLETED


# ---------------------------------------------------------------------------
# v8 scope/egress dead-code bug B: _check_plan_scope must check scope.include
# even when the plan carries no `target` (real catalog-style plans never do).
# ---------------------------------------------------------------------------


def _seed_approved_with_scope(repos, *, include: tuple[str, ...]) -> None:
    """Seed an APPROVED assessment whose scope.include holds the scan targets,
    with a CATALOG-STYLE plan (no `target` in step.parameters - the real
    planner output)."""
    from datetime import UTC, datetime

    from secopent.domain.policy.models import ExecutionMode, RiskClass
    from secopent.domain.projects.models import Project
    from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot

    repos.projects.add(Project.create(project_id="p1", name="t"))
    repos.scopes.add_snapshot(ScopeSnapshot(
        id="s1", project_id="p1", include=include, exclude=(),
        ports=(443,),
        limits=ScopeLimits(requests_per_second=10, concurrency=2, max_requests=100),
        approved_by="a", approved_at=datetime.now(UTC), digest="sha256:scope",
    ))
    service = AssessmentService(repos.assessments)
    assessment = service.create(
        project_id="p1", scope_snapshot_id="s1", mode=ExecutionMode.APPROVAL,
    )
    from secopent.domain.assessments.models import PlanStep
    service.attach_plan(assessment.id, steps=(
        PlanStep(
            key="web_app:wstg-info-01", runner="nuclei", risk=RiskClass.PASSIVE,
            parameters={"asset_type": "web_app", "test_class": "wstg-info-01"},
            dependencies=(),
        ),
    ))
    service.approve(
        assessment_id=assessment.id, approved_by="analyst",
        approved_risks=frozenset({RiskClass.PASSIVE}),
        approved_capabilities=frozenset(), scope_digest="sha256:scope",
    )
    return repos.assessments.get(assessment.id)


def test_scope_include_metadata_ip_blocked_by_egress_with_catalog_plan(
    memory_repositories,
) -> None:
    """v8 bug B: a scope that mistakenly includes the cloud-metadata IP is
    blocked by egress_guard EVEN THOUGH the plan carries no `target` field
    (real catalog plans). Previously _check_plan_scope skipped every step and
    the metadata IP was never checked."""
    from secopent.infrastructure.egress.egress_guard import EgressGuard
    from secopent.infrastructure.egress.nft_scope import SocketDnsResolver

    _seed_approved_with_scope(
        memory_repositories, include=("https://169.254.169.254/",)
    )
    assessment = memory_repositories.assessments.items[
        next(iter(memory_repositories.assessments.items))
    ]
    AssessmentService(memory_repositories.assessments).start(assessment.id)

    execute_assessment(
        assessment_id=assessment.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
        egress_guard=EgressGuard(SocketDnsResolver()),
    )

    assessment = memory_repositories.assessments.get(assessment.id)
    assert assessment is not None
    assert assessment.status is AssessmentStatus.FAILED
    actions = [e.action for e in memory_repositories.audit.events]
    assert "assessment.blocked.egress_denied" in actions


def test_scope_include_in_scope_target_proceeds_with_catalog_plan(
    memory_repositories,
) -> None:
    """A legitimate in-scope target (non-metadata, HTTP-prefixed IP rule) must
    NOT be blocked by the scope check when the plan carries no `target`."""
    from secopent.infrastructure.egress.egress_guard import EgressGuard
    from secopent.infrastructure.egress.nft_scope import SocketDnsResolver

    _seed_approved_with_scope(
        memory_repositories, include=("https://8.133.200.235/",)
    )
    assessment = memory_repositories.assessments.items[
        next(iter(memory_repositories.assessments.items))
    ]
    AssessmentService(memory_repositories.assessments).start(assessment.id)

    execute_assessment(
        assessment_id=assessment.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
        egress_guard=EgressGuard(SocketDnsResolver()),
    )

    assessment = memory_repositories.assessments.get(assessment.id)
    assert assessment is not None
    assert assessment.status is AssessmentStatus.COMPLETED
    actions = [e.action for e in memory_repositories.audit.events]
    assert "assessment.blocked.egress_denied" not in actions
