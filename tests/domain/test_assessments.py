from __future__ import annotations

import pytest

from secopent.domain.assessments.models import (
    Approval,
    Assessment,
    AssessmentStatus,
    ExecutionPlan,
    PlanStep,
)
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.policy.models import ExecutionMode, RiskClass


def _step(key: str, **kwargs) -> PlanStep:
    defaults = {
        "runner": "builtin:dns",
        "risk": RiskClass.LOW,
        "parameters": {},
        "dependencies": (),
    }
    defaults.update(kwargs)
    return PlanStep(key=key, **defaults)


def test_plan_digest_changes_with_parameters() -> None:
    one = ExecutionPlan.create(plan_id="p1", assessment_id="a1", version=1,
        steps=(_step("dns"),))
    two = ExecutionPlan.create(plan_id="p2", assessment_id="a1", version=1,
        steps=(_step("dns", parameters={"timeout": 5}),))
    assert one.digest != two.digest


def test_plan_rejects_duplicate_keys() -> None:
    with pytest.raises(DomainValidationError, match="unique"):
        ExecutionPlan.create(plan_id="p", assessment_id="a", version=1,
            steps=(_step("dns"), _step("dns")))


def test_plan_rejects_cycle() -> None:
    with pytest.raises(DomainValidationError, match="cycle"):
        ExecutionPlan.create(plan_id="p", assessment_id="a", version=1,
            steps=(_step("a", dependencies=("b",)), _step("b", dependencies=("a",))))


def test_plan_rejects_missing_dependency() -> None:
    with pytest.raises(DomainValidationError, match="dependency does not exist"):
        ExecutionPlan.create(plan_id="p", assessment_id="a", version=1,
            steps=(_step("a", dependencies=("missing",)),))


def test_approval_requires_digests() -> None:
    with pytest.raises(DomainValidationError, match="digest"):
        Approval.create(approval_id="x", assessment_id="a", plan_digest="",
            scope_digest="", mode=ExecutionMode.APPROVAL,
            approved_risks=frozenset({RiskClass.LOW}),
            approved_capabilities=frozenset(), approved_by="u")


def test_assessment_cannot_start_without_approval() -> None:
    assessment = Assessment.create(assessment_id="a", project_id="p",
        scope_snapshot_id="s", mode=ExecutionMode.APPROVAL)
    with pytest.raises(DomainValidationError, match="approval"):
        assessment.start(plan_id="plan", approval_id=None)


def test_assessment_start_moves_to_queued() -> None:
    assessment = Assessment.create(assessment_id="a", project_id="p",
        scope_snapshot_id="s", mode=ExecutionMode.APPROVAL)
    started = assessment.start(plan_id="plan", approval_id="appr-1")
    assert started.status is AssessmentStatus.QUEUED
    assert started.active_plan_id == "plan"
    assert started.approval_id == "appr-1"


def test_assessment_rejects_empty_ids() -> None:
    with pytest.raises(DomainValidationError, match="identifiers"):
        Assessment.create(assessment_id="", project_id="p", scope_snapshot_id="s",
            mode=ExecutionMode.APPROVAL)
