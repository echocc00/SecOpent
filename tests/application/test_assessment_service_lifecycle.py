"""Application layer: AssessmentService pause/resume/cancel/status (MCP §13).

The 5 control-plane methods (status/pause/resume/cancel) added for the MCP
orchestration surface. They persist status transitions through the state
machine AND write a durable control signal (ControlState) so the executor can
act at step boundaries (M3); approve/reject/start keep their human gate.
"""
from __future__ import annotations

from dataclasses import replace

import pytest

from secopent.application.assessments import (
    AssessmentPermissionError,
    AssessmentService,
)
from secopent.domain.assessments.models import (
    AssessmentStatus,
    ControlState,
)
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.policy.models import ExecutionMode, RiskClass


@pytest.fixture
def service(memory_repositories):  # noqa: ANN001
    return AssessmentService(memory_repositories.assessments)


def _drive_to_running(service: AssessmentService, repo) -> str:  # noqa: ANN001
    """DRAFT -> ... -> RUNNING through the persistence-only state machine."""
    created = service.create(
        project_id="p1", scope_snapshot_id="s1", mode=ExecutionMode.APPROVAL
    )
    queued = replace(created, status=AssessmentStatus.QUEUED)
    repo.add(queued)
    running = service.mark_running(queued.id)
    assert running.status is AssessmentStatus.RUNNING
    return running.id


def test_status_returns_assessment_or_raises_lookup(
    service, memory_repositories  # noqa: ANN001
) -> None:
    with pytest.raises(LookupError):
        service.status("nope")
    created = service.create(
        project_id="p1", scope_snapshot_id="s1", mode=ExecutionMode.APPROVAL
    )
    assert service.status(created.id).id == created.id
    assert service.status(created.id).status is AssessmentStatus.DRAFT


def test_pause_resume_cancel_round_trip(
    service, memory_repositories  # noqa: ANN001
) -> None:
    aid = _drive_to_running(service, memory_repositories.assessments)

    paused = service.pause(aid)
    assert paused.status is AssessmentStatus.PAUSED

    resumed = service.resume(paused.id)
    assert resumed.status is AssessmentStatus.RUNNING

    cancelled = service.cancel(resumed.id)
    assert cancelled.status is AssessmentStatus.CANCELLED

    # Terminal states reject further control-plane moves.
    with pytest.raises(DomainValidationError):
        service.pause(cancelled.id)


def test_cancel_from_queued_and_paused(
    service, memory_repositories  # noqa: ANN001
) -> None:
    created = service.create(
        project_id="p1", scope_snapshot_id="s1", mode=ExecutionMode.APPROVAL
    )
    queued = replace(created, status=AssessmentStatus.QUEUED)
    memory_repositories.assessments.add(queued)
    assert service.cancel(queued.id).status is AssessmentStatus.CANCELLED

    aid = _drive_to_running(service, memory_repositories.assessments)
    paused = service.pause(aid)
    assert service.cancel(paused.id).status is AssessmentStatus.CANCELLED


def test_pause_illegal_from_early_states(
    service, memory_repositories  # noqa: ANN001
) -> None:
    """DRAFT or QUEUED cannot pause; only RUNNING can."""
    created = service.create(
        project_id="p1", scope_snapshot_id="s1", mode=ExecutionMode.APPROVAL
    )
    with pytest.raises(DomainValidationError):
        service.pause(created.id)
    queued = replace(created, status=AssessmentStatus.QUEUED)
    memory_repositories.assessments.add(queued)
    with pytest.raises(DomainValidationError):
        service.pause(queued.id)


def test_human_gate_untouched_for_approve_reject_start(service) -> None:  # noqa: ANN001
    """The MCP-added methods do not weaken the LLM boundary."""
    with pytest.raises(AssessmentPermissionError):
        service.approve(
            assessment_id="x", approved_by="a",
            approved_risks=frozenset({RiskClass.PASSIVE}),
            approved_capabilities=frozenset(), scope_digest="d",
            actor_role="agent",
        )
    with pytest.raises(AssessmentPermissionError):
        service.reject(
            assessment_id="x", rejected_by="a", reason="r", actor_role="agent"
        )
    with pytest.raises(AssessmentPermissionError):
        service.start("x", actor_role="agent")
    with pytest.raises(AssessmentPermissionError):  # unknown roles rejected too
        service.approve(
            assessment_id="x", approved_by="a",
            approved_risks=frozenset(), approved_capabilities=frozenset(),
            scope_digest="d", actor_role="root",
        )


def test_control_signals_are_durable_with_status(
    service, memory_repositories  # noqa: ANN001
) -> None:
    """Each control move writes the matching durable signal (M3)."""
    aid = _drive_to_running(service, memory_repositories.assessments)
    assert service.pause(aid).control is ControlState.PAUSE_REQUESTED
    assert service.resume(aid).control is ControlState.RESUME_REQUESTED
    assert service.cancel(aid).control is ControlState.CANCEL_REQUESTED
    # The signal persists through the store (repo.get sees it).
    assert service.status(aid).control is ControlState.CANCEL_REQUESTED


def test_terminal_status_guard_cannot_be_overwritten(
    service, memory_repositories  # noqa: ANN001
) -> None:
    """mark_running/complete/fail refuse to leave the CANCELLED terminal state.

    The state machine (transitions.py) has no exits from CANCELLED, so the
    executor can never overwrite a cancelled assessment (design §3.2 fix).
    """
    aid = _drive_to_running(service, memory_repositories.assessments)
    service.cancel(aid)
    for call in (
        lambda: service.mark_running(aid),
        lambda: service.complete(aid),
        lambda: service.fail(aid, reason="late failure"),
    ):
        with pytest.raises(DomainValidationError):
            call()

    # A paused assessment cannot be completed by the executor either - it must
    # be resumed (or cancelled) first: the control plane owns the state.
    aid2 = _drive_to_running(service, memory_repositories.assessments)
    service.pause(aid2)
    with pytest.raises(DomainValidationError):
        service.complete(aid2)