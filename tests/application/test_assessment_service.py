from __future__ import annotations
from secopent.application.assessments import AssessmentService
from secopent.domain.policy.models import ExecutionMode


def test_create_assessment_persists(memory_repositories):
    service = AssessmentService(memory_repositories.assessments)
    assessment = service.create(project_id="p", scope_snapshot_id="s", mode=ExecutionMode.APPROVAL)
    assert memory_repositories.assessments.get(assessment.id) == assessment


def test_attach_plan_moves_to_awaiting_approval(memory_repositories):
    service = AssessmentService(memory_repositories.assessments)
    assessment = service.create(project_id="p", scope_snapshot_id="s", mode=ExecutionMode.APPROVAL)
    result = service.attach_plan(assessment.id, steps=())
    assert result.status.value == "awaiting_approval"
