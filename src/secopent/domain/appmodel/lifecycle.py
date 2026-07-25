# src/secopent/domain/appmodel/lifecycle.py
"""AppModel lifecycle state machine (§11.5/§11.9).

An AppModel moves DRAFT -> LLM_PROPOSED -> HUMAN_VALIDATED -> SIGNED ->
PUBLISHED -> SUPERSEDED. The LLM may PROPOSE a model (from traffic or docs) but
a human must VALIDATE and sign it; a PUBLISHED model is never deleted - a new
version SUPERSEDES it (old versions stay for audit/replay).
"""
from __future__ import annotations

from enum import StrEnum


class AppModelStatus(StrEnum):
    """AppModel lifecycle states."""

    DRAFT = "draft"
    LLM_PROPOSED = "llm_proposed"
    HUMAN_VALIDATED = "human_validated"
    SIGNED = "signed"
    PUBLISHED = "published"
    SUPERSEDED = "superseded"


# Allowed lifecycle transitions. A manually-built model may go DRAFT ->
# HUMAN_VALIDATED directly (skipping LLM_PROPOSED); SUPERSEDED is terminal.
_VALID_TRANSITIONS: dict[AppModelStatus, frozenset[AppModelStatus]] = {
    AppModelStatus.DRAFT: frozenset(
        {AppModelStatus.LLM_PROPOSED, AppModelStatus.HUMAN_VALIDATED}
    ),
    AppModelStatus.LLM_PROPOSED: frozenset(
        {AppModelStatus.HUMAN_VALIDATED, AppModelStatus.DRAFT}
    ),
    AppModelStatus.HUMAN_VALIDATED: frozenset({AppModelStatus.SIGNED}),
    AppModelStatus.SIGNED: frozenset({AppModelStatus.PUBLISHED}),
    AppModelStatus.PUBLISHED: frozenset({AppModelStatus.SUPERSEDED}),
    AppModelStatus.SUPERSEDED: frozenset(),
}


def can_transition(source: AppModelStatus, target: AppModelStatus) -> bool:
    """Whether a lifecycle transition source -> target is allowed."""
    return target in _VALID_TRANSITIONS.get(source, frozenset())
