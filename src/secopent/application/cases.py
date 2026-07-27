# src/secopent/application/cases.py
"""CaseService: case lifecycle + validation gate (§11.5/§11.8).

YAML cases move through DRAFT -> VALIDATED -> REVIEWED -> SIGNED -> PUBLISHED.
``validate`` runs the static RiskAnalyzer gate (deny patterns / undeclared risk).
Per §11.8 and the LLM边界, an agent may create and validate a case but can NEVER
review, sign, or publish it - those are human-only actions. Transitions must
follow the lifecycle order.

The in-memory registry is M2 scope; durable CaseRegistry persistence lands in M4
behind the same service surface.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

from ..domain.cases.models import CaseDefinition, CaseOrigin, CaseStatus
from ..domain.common.errors import DomainError
from ..domain.policy.models import RiskClass
from .risk_analyzer import RiskAnalyzer

# Signer signs a case's canonical payload bytes and returns a signature string.
CaseSigner = Callable[[bytes], str]

# Allowed lifecycle transitions (YAML case path, §11.5).
_TRANSITIONS: dict[CaseStatus, set[CaseStatus]] = {
    CaseStatus.DRAFT: {CaseStatus.VALIDATED},
    CaseStatus.VALIDATED: {CaseStatus.REVIEWED},
    CaseStatus.REVIEWED: {CaseStatus.SIGNED},
    CaseStatus.SIGNED: {CaseStatus.PUBLISHED},
}

_HUMAN_ONLY = "human"
_AGENT = "agent"


class CaseNotFoundError(DomainError):
    """Raised when a case id is not in the registry."""


class CasePermissionError(DomainError):
    """Raised when an agent attempts a human-only action (review/sign/publish)."""


class CaseTransitionError(DomainError):
    """Raised on an out-of-order lifecycle transition."""


class CaseNotModelGeneratedError(DomainError):
    """Raised when the model-generated fast path is applied to a non-model case."""


def _signing_payload(case: CaseDefinition) -> bytes:
    """A stable canonical payload to sign for a case version."""
    return "|".join(
        [case.id, case.version, case.risk.value, case.target_type, case.schema]
    ).encode("utf-8")


class CaseService:
    """Manage the case lifecycle and enforce the publish gate + human-only steps."""

    def __init__(self, risk_analyzer: RiskAnalyzer) -> None:
        self._risk = risk_analyzer
        self._cases: dict[str, CaseDefinition] = {}

    def create_draft(self, case: CaseDefinition) -> CaseDefinition:
        """Register a case as a DRAFT (agents may do this)."""
        draft = replace(case, status=CaseStatus.DRAFT)
        self._cases[draft.id] = draft
        return draft

    def get(self, case_id: str) -> CaseDefinition:
        case = self._cases.get(case_id)
        if case is None:
            raise CaseNotFoundError(f"case not found: {case_id}")
        return case

    def list_all(self) -> list[CaseDefinition]:
        """Return all registered cases (any status), ordered by id."""
        return [self._cases[key] for key in sorted(self._cases)]

    def validate(self, case_id: str) -> CaseDefinition:
        """Run the static RiskAnalyzer gate; DRAFT -> VALIDATED (agents may do this)."""
        case = self.get(case_id)
        self._risk.enforce_publish(case)  # raises RiskPublishDenied / RiskUndeclared
        return self._transition(case, CaseStatus.VALIDATED)

    def review(self, case_id: str, *, actor_role: str) -> CaseDefinition:
        """Human-only: VALIDATED -> REVIEWED."""
        self._require_human(actor_role)
        return self._transition(self.get(case_id), CaseStatus.REVIEWED)

    def sign(self, case_id: str, *, signer: CaseSigner, actor_role: str) -> CaseDefinition:
        """Human-only: REVIEWED -> SIGNED, applying the Ed25519-style signature."""
        self._require_human(actor_role)
        case = self.get(case_id)
        self._check_transition(case, CaseStatus.SIGNED)
        signed = replace(
            case, status=CaseStatus.SIGNED, signature=signer(_signing_payload(case))
        )
        self._cases[case_id] = signed
        return signed

    def publish(self, case_id: str, *, actor_role: str) -> CaseDefinition:
        """Human-only: SIGNED -> PUBLISHED."""
        self._require_human(actor_role)
        return self._transition(self.get(case_id), CaseStatus.PUBLISHED)

    def fast_track_model_generated(self, case_id: str) -> CaseDefinition:
        """Deterministic fast path for cases generated from a SIGNED AppModel (§11.8).

        A model-generated case inherits trust from the human-signed model, so it
        auto-passes the risk gate and (for Passive/Low risk) auto-advances to
        REVIEWED without a separate human review. Intrusive/Active cases still
        stop at VALIDATED and require human review. This is a deterministic
        policy (trust transfer), not an LLM judgment - signing/publishing remain
        human-only via ``sign``/``publish``.
        """
        case = self.get(case_id)
        if case.origin is not CaseOrigin.MODEL_GENERATED:
            raise CaseNotModelGeneratedError(
                f"case {case_id} is not model-generated (origin={case.origin.value})"
            )
        self._risk.enforce_publish(case)  # raises RiskPublishDenied / RiskUndeclared
        validated = self._transition(case, CaseStatus.VALIDATED)
        if case.risk in (RiskClass.PASSIVE, RiskClass.LOW):
            return self._transition(validated, CaseStatus.REVIEWED)
        return validated

    def _transition(self, case: CaseDefinition, to_status: CaseStatus) -> CaseDefinition:
        self._check_transition(case, to_status)
        updated = replace(case, status=to_status)
        self._cases[case.id] = updated
        return updated

    def _check_transition(self, case: CaseDefinition, to_status: CaseStatus) -> None:
        allowed = _TRANSITIONS.get(case.status, set())
        if to_status not in allowed:
            raise CaseTransitionError(
                f"case {case.id}: cannot transition {case.status.value} -> {to_status.value}"
            )

    @staticmethod
    def _require_human(actor_role: str) -> None:
        if actor_role == _AGENT:
            raise CasePermissionError(
                "agents cannot review, sign, or publish cases (human-only action)"
            )
        if actor_role != _HUMAN_ONLY:
            raise CasePermissionError(f"unknown actor role: {actor_role!r}")
