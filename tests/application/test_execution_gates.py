# tests/application/test_execution_gates.py
"""execute_assessment security gates (W2-A Tasks 2-5).

Tests the wiring of EmergencyStop, PermitSigner/Verifier, ScopeEnforcer, and
AuditChain into the execution path. Reuses the seed/step-runner helpers from
test_execution.py to avoid duplication.
"""
from __future__ import annotations

# Reuse the seed/fake helpers defined in the sibling execution test module.
from test_execution import (  # type: ignore[import-not-found]
    _FakeStepRunner,
    _MemoryFindingRepo,
    _observation,
    _seed_approved,
)

from secopent.application.assessments import AssessmentService
from secopent.application.audit import AuditService
from secopent.application.emergency_stop import EmergencyStop
from secopent.application.execution import execute_assessment
from secopent.domain.assessments.models import AssessmentStatus
from secopent.infrastructure.safety.emergency_infra import NullContainerTerminator
from secopent.infrastructure.safety.permit_revoker import InMemoryPermitRevoker

# --- T2: EmergencyStop gate -------------------------------------------------


def test_execute_refuses_when_emergency_stop_triggered(memory_repositories) -> None:
    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)  # -> QUEUED

    stop = EmergencyStop(
        permit_revoker=InMemoryPermitRevoker(),
        container_terminator=NullContainerTerminator(),
        audit=AuditService(memory_repositories.audit),
    )
    stop.trigger(actor="ops", reason="manual kill switch")

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
        emergency_stop=stop,
    )

    assessment = memory_repositories.assessments.get(a.id)
    assert assessment is not None
    assert assessment.status is AssessmentStatus.FAILED
    actions = [e.action for e in memory_repositories.audit.events]
    assert "assessment.blocked.emergency_stop" in actions
    assert "assessment.completed" not in actions


# --- T3: Permit signing -----------------------------------------------------


def test_start_assessment_signs_permit_bound_to_scope_and_plan(
    memory_repositories,
) -> None:
    from secopent.domain.permits.models import ExecutionPermit
    from secopent.infrastructure.permits.permit_signer import PermitSigner

    a = _seed_approved(memory_repositories)
    AssessmentService(memory_repositories.assessments).start(a.id)  # -> QUEUED

    real_signer = PermitSigner()
    captured: list[ExecutionPermit] = []

    class _CapturingSigner:
        def issue(self, permit: ExecutionPermit) -> ExecutionPermit:
            signed = real_signer.issue(permit)
            captured.append(signed)
            return signed

    revoker = InMemoryPermitRevoker()

    execute_assessment(
        assessment_id=a.id,
        assessment_repo=memory_repositories.assessments,
        scope_repo=memory_repositories.scopes,
        finding_repo=_MemoryFindingRepo(),
        audit_repo=memory_repositories.audit,
        step_runner_factory=lambda scope: _FakeStepRunner((_observation(),)),
        permit_signer=_CapturingSigner(),
        permit_registry=revoker,
    )

    assert len(captured) == 1
    permit = captured[0]
    assert permit.signature  # non-empty Ed25519 signature
    assert permit.worker_id == "adapter-executor"
    assert permit.job_id == a.id

    assessment = memory_repositories.assessments.get(a.id)
    assert assessment is not None
    plan = memory_repositories.assessments.get_plan(assessment.active_plan_id)
    scope = memory_repositories.scopes.get_snapshot(assessment.scope_snapshot_id)
    assert plan is not None and scope is not None
    assert permit.scope_digest == scope.digest
    assert permit.plan_digest == plan.digest

    # nonce registered with the revoker so EmergencyStop can revoke it
    assert revoker.revoke_unused() == 1
