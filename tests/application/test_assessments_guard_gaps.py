"""Service-level regression for the two pre-T7 guard gaps (v0.3.0 T7).

Before the data-driven transition table, ``attach_plan`` and ``approve``
performed NO status check: a plan could be re-attached to an APPROVED
assessment and a REJECTED assessment could be approved again. Both are
illegal transitions and must now raise.
"""
from __future__ import annotations

import pytest
from test_execution import _seed_approved  # type: ignore[import-not-found]

from secopent.application.assessments import AssessmentService
from secopent.domain.assessments.models import AssessmentStatus, PlanStep
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.policy.models import RiskClass


def _step() -> PlanStep:
    return PlanStep(
        key="recon", runner="nuclei", risk=RiskClass.LOW,
        parameters={"target": "http://target"}, dependencies=(),
    )


def test_attach_plan_rejected_on_approved_assessment(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    """APPROVED -> AWAITING_APPROVAL is illegal (gap fix #1)."""
    assessment = _seed_approved(memory_repositories)
    service = AssessmentService(memory_repositories.assessments)
    with pytest.raises(DomainValidationError, match="illegal assessment transition"):
        service.attach_plan(assessment.id, steps=(_step(),))
    # Status unchanged.
    assert (
        memory_repositories.assessments.get(assessment.id).status
        is AssessmentStatus.APPROVED
    )


def test_attach_plan_rejected_on_running_assessment(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    assessment = _seed_approved(memory_repositories)
    service = AssessmentService(memory_repositories.assessments)
    service.start(assessment.id)
    service.mark_running(assessment.id)
    with pytest.raises(DomainValidationError, match="illegal assessment transition"):
        service.attach_plan(assessment.id, steps=(_step(),))


def test_replan_while_awaiting_approval_is_legal(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    """AWAITING_APPROVAL -> AWAITING_APPROVAL (re-plan) stays legal."""
    assessment = _seed_approved(memory_repositories)
    service = AssessmentService(memory_repositories.assessments)
    fresh = service.create(
        project_id="p", scope_snapshot_id="s",
        mode=memory_repositories.assessments.get(assessment.id).mode,
    )
    once = service.attach_plan(fresh.id, steps=(_step(),))
    assert once.status is AssessmentStatus.AWAITING_APPROVAL
    twice = service.attach_plan(fresh.id, steps=(_step(),))
    assert twice.status is AssessmentStatus.AWAITING_APPROVAL


def test_approve_rejected_assessment_raises(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    """REJECTED -> APPROVED is illegal even though the plan is attached (gap
    fix #2 - before T7 this succeeded because approve checked no status)."""
    assessment = _seed_approved(memory_repositories)
    service = AssessmentService(memory_repositories.assessments)
    # Bring a fresh assessment to REJECTED (reject requires AWAITING_APPROVAL).
    fresh = service.create(
        project_id="p", scope_snapshot_id="s",
        mode=memory_repositories.assessments.get(assessment.id).mode,
    )
    service.attach_plan(fresh.id, steps=(_step(),))
    service.reject(
        assessment_id=fresh.id, rejected_by="analyst", reason="scope changed"
    )
    assert (
        memory_repositories.assessments.get(fresh.id).status
        is AssessmentStatus.REJECTED
    )
    with pytest.raises(DomainValidationError, match="illegal assessment transition"):
        service.approve(
            assessment_id=fresh.id, approved_by="analyst",
            approved_risks=frozenset({RiskClass.LOW}),
            approved_capabilities=frozenset(), scope_digest="sha256:scope",
        )
    assert (
        memory_repositories.assessments.get(fresh.id).status
        is AssessmentStatus.REJECTED
    )
