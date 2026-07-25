from __future__ import annotations

import uuid
from dataclasses import replace

from ..domain.assessments.models import Assessment, AssessmentStatus, ExecutionPlan, PlanStep
from ..domain.policy.models import ExecutionMode
from .ports.repositories import AssessmentRepository


class AssessmentService:
    def __init__(self, repo: AssessmentRepository) -> None:
        self._repo = repo

    def create(self, *, project_id: str, scope_snapshot_id: str,
               mode: ExecutionMode) -> Assessment:
        assessment = Assessment.create(
            assessment_id=f"asm-{uuid.uuid4().hex[:12]}",
            project_id=project_id, scope_snapshot_id=scope_snapshot_id, mode=mode,
        )
        self._repo.add(assessment)
        return assessment

    def attach_plan(self, assessment_id: str, steps: tuple[PlanStep, ...]) -> Assessment:
        assessment = self._repo.get(assessment_id)
        if assessment is None:
            raise LookupError(f"assessment {assessment_id} not found")
        plan = ExecutionPlan.create(
            plan_id=f"plan-{uuid.uuid4().hex[:12]}",
            assessment_id=assessment_id, version=1, steps=steps,
        )
        self._repo.save_plan(plan)
        updated = replace(
            assessment,
            status=AssessmentStatus.AWAITING_APPROVAL,
            active_plan_id=plan.id,
        )
        self._repo.add(updated)
        return updated
