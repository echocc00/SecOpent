"""LoopOracleVerifier — drive request_oracle steps through OracleEngine (v0.7.6, Task 6).

The loop's ``request_oracle`` action reuses the existing OracleEngine + the
verifier-factory dispatch unchanged: this coordinator resolves the referenced
candidate by id, asks the injected factory for the per-candidate verifier
(DiffSemanticVerifier for logic methods, the rescan verifier otherwise), and runs
the N/N engine. ``OracleEngine`` is never modified here.

The only loop-specific rule is the spec §5 guard: a LOGIC candidate (a
``diff_semantic`` method, e.g. IDOR / auth bypass / priv-esc) with no diff spec
must be INCONCLUSIVE, never a reflexive REFUTED. A missing spec is a lack of
evidence, not a disproof. Without this guard the DiffSemanticVerifier would
report FAILURE per reproduction and aggregate to REFUTED — the exact
mis-verdict §5 forbids. The guard is enforced here BEFORE the engine runs.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ...domain.verification.models import (
    CandidateFinding,
    VerificationStatus,
    VulnType,
)
from ...domain.verification.registry import VerificationMethodRegistry
from ..canary import CanaryTokenManager
from ..oracle import OracleEngine, OracleVerifier

CandidateProvider = Callable[[str], CandidateFinding | None]
# The factory builds a per-candidate OracleVerifier; it reads ``.asset`` and
# ``vuln_type`` off the finding-like passed in, so this is duck-typed rather
# than tied to the infrastructure RescanVerifierFactory's exact signature.
VerifierFactory = Callable[[Any, VulnType], OracleVerifier]


@dataclass(frozen=True, slots=True)
class OracleOutcome:
    """Aggregated result of one loop oracle verification (surfaced on LoopStep)."""

    status: VerificationStatus
    successes: int
    attempts: int
    reason: str

    @property
    def resolved(self) -> bool:
        """True when the oracle deterministically resolved the candidate.

        CONFIRMED and REFUTED are deterministic verdicts; INCONCLUSIVE / PENDING
        are not — a flaky or under-specified candidate is escalated to human
        review, never reported as progress (spec §5).
        """
        return self.status in (VerificationStatus.CONFIRMED, VerificationStatus.REFUTED)


class _FindingLike:
    """Minimal asset + vuln_type view so the verifier factory's probe building works.

    The factory's rescan branch reads ``finding.asset`` (probe URL) and the diff
    dispatch reads ``vuln_type``. A CandidateFinding has ``target``, not ``asset``;
    this adapter bridges the two without changing the factory signature.
    """

    __slots__ = ("asset", "vuln_type")

    def __init__(self, asset: str, vuln_type: VulnType) -> None:
        self.asset = asset
        self.vuln_type = vuln_type


class LoopOracleVerifier:
    """Resolve a candidate, pick its factory-dispatched verifier, run OracleEngine."""

    __slots__ = ("_registry", "_canary", "_verifier_factory", "_candidate_provider")

    def __init__(
        self,
        *,
        registry: VerificationMethodRegistry,
        canary: CanaryTokenManager,
        verifier_factory: VerifierFactory,
        candidate_provider: CandidateProvider,
    ) -> None:
        self._registry = registry
        self._canary = canary
        self._verifier_factory = verifier_factory
        self._candidate_provider = candidate_provider

    def verify(
        self, candidate_id: str, *, actor: str, session: Any | None = None
    ) -> OracleOutcome:
        if not candidate_id:
            return self._inconclusive("no candidate_id in request_oracle payload")
        candidate = self._candidate_provider(candidate_id)
        if candidate is None:
            return self._inconclusive(f"candidate {candidate_id!r} not found")

        method = self._registry.require_method(candidate.vuln_type)
        # spec §5 guard: a LOGIC candidate without a diff spec is a lack of
        # evidence, not a disproof (see module docstring for why this must be
        # here rather than deferred to the DiffSemanticVerifier).
        if method.diff_semantic and candidate.diff is None:
            return self._inconclusive(
                f"logic candidate {candidate_id!r} has no diff spec (refusing to REFUTE)"
            )

        finding_like = _FindingLike(
            asset=candidate.target, vuln_type=candidate.vuln_type
        )
        verifier = self._verifier_factory(finding_like, candidate.vuln_type)
        engine = OracleEngine(
            registry=self._registry, verifier=verifier, canary=self._canary
        )
        result = engine.verify(candidate, actor=actor, session=session)
        return OracleOutcome(
            status=result.status,
            successes=result.successes,
            attempts=result.attempts,
            reason=result.reason,
        )

    def _inconclusive(self, reason: str) -> OracleOutcome:
        return OracleOutcome(
            status=VerificationStatus.INCONCLUSIVE,
            successes=0,
            attempts=0,
            reason=reason,
        )
