# src/secopent/domain/verification/diff_semantic.py
"""DIFF_SEMANTIC deterministic assertions (spec §5).

Logic vulns (IDOR / auth bypass / priv-esc) leak data as STRUCTURAL
differences between two requests to the same business object, not as a
reflection/OOB echo. The loop proposer supplies the two requests + an
expectation; the oracle decides with deterministic structure-diff + state
readback. The LLM never marks Confirmed.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..common.errors import DomainValidationError


class Expectation(StrEnum):
    """The differential expectation the proposer attaches to a diff check."""

    DENY = "deny"
    SINGLE_SPEND = "single_spend"
    STATE_REJECT = "state_reject"
    STATE_CHANGE = "state_change"


@dataclass(frozen=True, slots=True)
class DiffSemanticPayload:
    """The two requests + expectation defining a differential confirmation.

    ``baseline_request`` is a request that is *allowed* for the actor; the
    ``assertion_request`` is the suspect override. ``expectation`` states how a
    confirmation is decided (DENY/SINGLE_SPEND/STATE_REJECT/STATE_CHANGE).
    ``state_readback`` (optional) is a URL whose response is read back after the
    assertion to confirm a state effect for single-spend style expectations.
    """

    candidate_id: str
    baseline_request: dict[str, object]
    assertion_request: dict[str, object]
    expectation: Expectation
    state_readback: str | None = None

    def __post_init__(self) -> None:
        if not self.candidate_id:
            raise DomainValidationError("DiffSemanticPayload.candidate_id required")
        for name in ("baseline_request", "assertion_request"):
            value = getattr(self, name)
            if not isinstance(value, dict) or not value:
                raise DomainValidationError(f"{name} must be a non-empty dict")
