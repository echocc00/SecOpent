# src/secopent/application/oracle.py
"""OracleEngine: deterministic N/N verification of candidate findings (§9, ADR-004).

A low-trust Observation promoted to a CandidateFinding is verified by running N
independent reproductions through an injected verifier (the self-built
RescanVerifier in production - real rescan N/N reproduction, ADR-014 revised)
and aggregating with the deterministic ``decide_outcome`` rule.
Each reproduction carries a fresh single-use canary token. A finding is
CONFIRMED only at N/N successes; server errors (5xx) count as INCONCLUSIVE,
never REFUTED.

The LLM is never in the confirmation path - only the oracle decides, via
deterministic code (LLM边界). ``confirm`` promotes a CONFIRMED result to a
ConfirmedFinding and refuses anything else.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from ..domain.common.errors import DomainValidationError
from ..domain.verification.models import (
    CandidateFinding,
    ConfirmedFinding,
    ReproductionStatus,
    VerificationMethod,
    VerificationResult,
    VerificationStatus,
    decide_outcome,
)
from ..domain.verification.registry import VerificationMethodRegistry
from .canary import CanaryTokenManager


@runtime_checkable
class OracleVerifier(Protocol):
    """One independent reproduction executed by the oracle backend.

    Returns SUCCESS / FAILURE / SERVER_ERROR. In production this is the
    self-built RescanVerifier (real rescan reproduction); in tests a scripted
    fake. The verifier is responsible for checking the canary echo/OOB and
    reporting the outcome.
    """

    def reproduce(
        self,
        candidate: CandidateFinding,
        method: VerificationMethod,
        *,
        canary_token: str,
        session: Any = None,
    ) -> ReproductionStatus: ...


class OracleEngine:
    """Run N/N verification and promote confirmed findings."""

    def __init__(
        self,
        *,
        registry: VerificationMethodRegistry,
        verifier: OracleVerifier,
        canary: CanaryTokenManager,
    ) -> None:
        self._registry = registry
        self._verifier = verifier
        self._canary = canary

    def verify(
        self, candidate: CandidateFinding, *, actor: str, session: Any = None
    ) -> VerificationResult:
        """Run the method's N independent reproductions and aggregate the result.

        Exactly ``method.default_n`` attempts are run; server-error attempts are
        counted as inconclusive. The deterministic ``decide_outcome`` rule turns
        the tallies into CONFIRMED / REFUTED / INCONCLUSIVE.
        """
        method = self._registry.require_method(candidate.vuln_type)
        successes = 0
        inconclusive = 0
        attempts = 0
        for _ in range(method.default_n):
            token = self._canary.generate(
                actor=actor, candidate_id=candidate.id, session=session
            )
            status = self._verifier.reproduce(
                candidate, method, canary_token=token, session=session
            )
            attempts += 1
            if status is ReproductionStatus.SUCCESS:
                successes += 1
            elif status is ReproductionStatus.SERVER_ERROR:
                inconclusive += 1
        outcome = decide_outcome(
            method,
            successes=successes,
            attempts=attempts,
            inconclusive_count=inconclusive,
        )
        reason = (
            f"{outcome.value}: {successes}/{attempts} reproductions "
            f"({inconclusive} server errors)"
        )
        return VerificationResult(
            status=outcome, successes=successes, attempts=attempts, reason=reason
        )

    def confirm(
        self,
        candidate: CandidateFinding,
        result: VerificationResult,
        *,
        evidence_ids: tuple[str, ...],
        verified_at: datetime,
    ) -> ConfirmedFinding:
        """Promote a CONFIRMED result to a ConfirmedFinding (refuses otherwise)."""
        if result.status is not VerificationStatus.CONFIRMED:
            raise DomainValidationError(
                "only a CONFIRMED oracle result can become a ConfirmedFinding "
                f"(got {result.status.value})"
            )
        return ConfirmedFinding(
            candidate_id=candidate.id,
            vuln_type=candidate.vuln_type,
            evidence_ids=evidence_ids,
            verified_at=verified_at,
            successes=result.successes,
            attempts=result.attempts,
        )
