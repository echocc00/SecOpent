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
