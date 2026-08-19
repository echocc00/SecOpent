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
from .models import ReproductionStatus


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


@dataclass(frozen=True, slots=True)
class DiffResponse:
    """A single HTTP response captured for differential comparison."""

    status: int
    body: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class AssertionResult:
    """All inputs needed to decide one differential assertion verdict.

    ``base`` is the (allowed) baseline response A; ``assertion`` is the suspect
    override response B. ``refused`` is True when B was denied (e.g. 403/401/
    400). ``structure_same`` is True when ``base`` and ``assertion`` are
    structurally comparable. ``state_ok`` (optional) is the state-readback
    predicate used only by single-spend style expectations.
    """

    expectation: Expectation
    base: DiffResponse
    assertion: DiffResponse
    refused: bool
    structure_same: bool
    state_ok: bool | None = None


def decide_diff_outcome(r: AssertionResult) -> ReproductionStatus:
    """Deterministic per-expectation verdict on a differential assertion (spec §5).

    Each branch encodes whether the FINDING (vulnerability) is CONFIRMED. The
    success criteria are OPPOSITE between the two halves — do not merge them:

    - DENY / SINGLE_SPEND ("entitle an override"): the vuln is confirmed when the
      override is *embodied*, i.e. B is NOT refused AND has the SAME structure as
      the allowed baseline A (a越权 not denied). Refused => FAILURE (defense
      worked). Comparable-but-unequal structure (or un-comparable) => SERVER_ERROR
      (inconclusive, escalated to human — never reflexive REFUTE).
    - STATE_REJECT / STATE_CHANGE ("a state-machine bypass IS the finding"): the
      vuln is confirmed when the illegal migration is NOT refused — there is NO
      structure-same dependency. Refused => FAILURE.

    SINGLE_SPEND additionally consults the state readback: ``state_ok=False``
    (readback shows a bad state) => FAILURE. For non-single-spend expectations
    ``state_ok`` is ignored.

    Unrecognised expectation / no matching branch => SERVER_ERROR (inconclusive,
    escalated to human review, never a reflexive REFUTE).
    """
    exp = r.expectation

    # DENY: confirmed only when the override is embodied (not refused AND
    # same structure as the allowed baseline).
    if exp is Expectation.DENY:
        if not r.refused and r.structure_same:
            return ReproductionStatus.SUCCESS
        if r.refused:
            return ReproductionStatus.FAILURE
        # not refused but structure incomparable -> cannot tell a deny vs a
        # different object -> inconclusive, escalate to human.
        return ReproductionStatus.SERVER_ERROR

    # SINGLE_SPEND: like DENY (structure-same + not refused) but additionally
    # armed by the state readback — a bad readback refutes.
    if exp is Expectation.SINGLE_SPEND:
        if r.state_ok is False:
            return ReproductionStatus.FAILURE
        if not r.refused and r.structure_same:
            return ReproductionStatus.SUCCESS
        if r.refused:
            return ReproductionStatus.FAILURE
        return ReproductionStatus.SERVER_ERROR

    # STATE_REJECT / STATE_CHANGE: the bypass IS the finding; confirmed when the
    # illegal migration is NOT refused (no structure-same dependency).
    if exp is Expectation.STATE_REJECT or exp is Expectation.STATE_CHANGE:
        if not r.refused:
            return ReproductionStatus.SUCCESS
        return ReproductionStatus.FAILURE

    # Unknown expectation -> inconclusive, escalate to human (never REFUTE).
    return ReproductionStatus.SERVER_ERROR
