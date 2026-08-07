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
