"""Assessment state machine: exhaustive transition-table tests (v0.3.0 T7).

The table in ``domain.assessments.transitions`` is the single source of
truth; these tests pin it completely: every status appears as a key, the
happy path is legal, terminals have no exits, and the full 12x12 matrix
behaves exactly as the table declares (144 cases).
"""
from __future__ import annotations

import pytest

from secopent.domain.assessments.models import AssessmentStatus
from secopent.domain.assessments.transitions import (
    ALLOWED_TRANSITIONS,
    assert_transition,
)
from secopent.domain.common.errors import DomainValidationError

ALL_STATUSES = tuple(AssessmentStatus)


def test_table_covers_every_status_exactly_once() -> None:
    assert set(ALLOWED_TRANSITIONS) == set(AssessmentStatus)


def test_all_targets_are_valid_statuses() -> None:
    for targets in ALLOWED_TRANSITIONS.values():
        for target in targets:
            assert isinstance(target, AssessmentStatus)


@pytest.mark.parametrize("current", ALL_STATUSES)
@pytest.mark.parametrize("target", ALL_STATUSES)
def test_transition_matrix(
    current: AssessmentStatus, target: AssessmentStatus
) -> None:
    """Exactly the table's pairs pass; every other pair raises."""
    if target in ALLOWED_TRANSITIONS[current]:
        assert_transition(current, target)  # must not raise
    else:
        with pytest.raises(
            DomainValidationError, match="illegal assessment transition"
        ):
            assert_transition(current, target)


def test_happy_path_chain_is_legal() -> None:
    chain = [
        (AssessmentStatus.DRAFT, AssessmentStatus.AWAITING_APPROVAL),
        (AssessmentStatus.AWAITING_APPROVAL, AssessmentStatus.APPROVED),
        (AssessmentStatus.APPROVED, AssessmentStatus.QUEUED),
        (AssessmentStatus.QUEUED, AssessmentStatus.RUNNING),
        (AssessmentStatus.RUNNING, AssessmentStatus.COMPLETED),
    ]
    for current, target in chain:
        assert_transition(current, target)


def test_pause_resume_cancel_chain_is_legal() -> None:
    """MCP control-plane semantics: RUNNING<->PAUSED, cancel from 3 states."""
    legal = [
        (AssessmentStatus.RUNNING, AssessmentStatus.PAUSED),
        (AssessmentStatus.PAUSED, AssessmentStatus.RUNNING),
        (AssessmentStatus.QUEUED, AssessmentStatus.CANCELLED),
        (AssessmentStatus.RUNNING, AssessmentStatus.CANCELLED),
        (AssessmentStatus.PAUSED, AssessmentStatus.CANCELLED),
    ]
    for current, target in legal:
        assert_transition(current, target)


def test_pause_resume_are_persistence_only_guards() -> None:
    """PAUSED has no executor-related exits; only resume/cancel."""
    assert ALLOWED_TRANSITIONS[AssessmentStatus.PAUSED] == frozenset(
        {AssessmentStatus.RUNNING, AssessmentStatus.CANCELLED}
    )


def test_replan_stays_awaiting_approval() -> None:
    assert_transition(
        AssessmentStatus.AWAITING_APPROVAL, AssessmentStatus.AWAITING_APPROVAL
    )


def test_terminal_statuses_have_no_exits() -> None:
    for status in (
        AssessmentStatus.REJECTED,
        AssessmentStatus.COMPLETED,
        AssessmentStatus.PARTIAL,
        AssessmentStatus.FAILED,
        AssessmentStatus.CANCELLED,
    ):
        assert ALLOWED_TRANSITIONS[status] == frozenset()


def test_error_message_names_both_statuses() -> None:
    with pytest.raises(
        DomainValidationError, match=r"approved -> running"
    ):
        assert_transition(AssessmentStatus.APPROVED, AssessmentStatus.RUNNING)
