"""Assessment state machine as data (v0.3.0 T7).

One table is the single source of truth for which status transitions are
legal; ``assert_transition`` is the ONLY guard the application layer needs.
Before this module, every service method carried its own ad-hoc ``if status is
not X: raise`` check - and two methods (``attach_plan``, ``approve``) had no
guard at all, so a REJECTED assessment could be re-approved.

Deliberate scope: enforcement lives at the application-service boundary
(the only production path that mutates assessment status). The domain
``Assessment`` dataclass stays a plain persistence-mapped value object, and
startup recovery (``create_app``) intentionally bypasses the table when it
maps crash-leftover RUNNING/QUEUED rows to FAILED - that transition exists
precisely because the normal state machine was interrupted.
"""
from __future__ import annotations

from collections.abc import Mapping

from ..common.errors import DomainValidationError
from .models import AssessmentStatus

ALLOWED_TRANSITIONS: Mapping[AssessmentStatus, frozenset[AssessmentStatus]] = {
    AssessmentStatus.DRAFT: frozenset({AssessmentStatus.AWAITING_APPROVAL}),
    # PLANNED/PAUSED are reserved statuses with no transitions today.
    AssessmentStatus.PLANNED: frozenset(),
    # Re-planning keeps the assessment in AWAITING_APPROVAL.
    AssessmentStatus.AWAITING_APPROVAL: frozenset({
        AssessmentStatus.APPROVED,
        AssessmentStatus.REJECTED,
        AssessmentStatus.AWAITING_APPROVAL,
    }),
    AssessmentStatus.APPROVED: frozenset({AssessmentStatus.QUEUED}),
    AssessmentStatus.REJECTED: frozenset(),  # terminal: a new assessment is the remedy
    AssessmentStatus.QUEUED: frozenset({AssessmentStatus.RUNNING}),
    AssessmentStatus.RUNNING: frozenset({
        AssessmentStatus.COMPLETED,
        AssessmentStatus.PARTIAL,
        AssessmentStatus.FAILED,
    }),
    AssessmentStatus.PAUSED: frozenset(),
    AssessmentStatus.COMPLETED: frozenset(),  # terminal
    AssessmentStatus.PARTIAL: frozenset(),    # terminal
    AssessmentStatus.FAILED: frozenset(),     # terminal: restart = explicit operator action
    AssessmentStatus.CANCELLED: frozenset(),  # terminal
}


def assert_transition(current: AssessmentStatus, target: AssessmentStatus) -> None:
    """Raise ``DomainValidationError`` unless ``current -> target`` is legal."""
    if target not in ALLOWED_TRANSITIONS.get(current, frozenset()):
        raise DomainValidationError(
            f"illegal assessment transition: {current.value} -> {target.value}"
        )
