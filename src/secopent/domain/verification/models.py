# src/secopent/domain/verification/models.py
"""Verification domain models (§9, ADR-004: oracle N/N, not LLM judgment).

A low-trust Observation becomes a *CandidateFinding*. The oracle verifies it by
reproducing the underlying behavior N independent times (N/N). Only when the
required N reproductions succeed is the candidate promoted to a
*ConfirmedFinding*. This module carries the curated verification knowledge
(``VerificationMethod`` per vulnerability type) and the deterministic N/N
decision rule (``decide_outcome``).

The LLM never marks a finding Confirmed - that decision is made here, in
deterministic code, by the oracle (LLM边界).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from ..common.errors import DomainValidationError


class VulnType(StrEnum):
    """The 14 curated vulnerability classes the oracle knows how to verify."""

    SQLI = "sqli"
    RCE = "rce"
    SSRF = "ssrf"
    XXE = "xxe"
    XSS = "xss"
    DESERIALIZATION = "deserialization"
    FILE_READ = "file_read"
    AUTH_BYPASS = "auth_bypass"
    PATH_TRAVERSAL = "path_traversal"
    IDOR = "idor"
    PARAM_TAMPERING = "param_tampering"
    MFA_BYPASS = "mfa_bypass"
    WEAK_CREDENTIALS = "weak_credentials"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class RetryStrategy(StrEnum):
    """How the oracle schedules its N independent reproductions.

    CROSS_WORKER (default) runs each reproduction on a different worker to avoid
    stateful false-positives; SAME_WORKER is the degraded fallback (≥2s interval)
    when only one worker is available.
    """

    CROSS_WORKER = "cross_worker"
    SAME_WORKER = "same_worker"


class VerificationStatus(StrEnum):
    """Outcome of an oracle verification attempt."""

    PENDING = "pending"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


class ReproductionStatus(StrEnum):
    """Outcome of a single independent reproduction by the oracle backend.

    ``SERVER_ERROR`` marks a 5xx / flaky-target attempt: it is counted as
    inconclusive, never as a refutation.
    """

    SUCCESS = "success"
    FAILURE = "failure"
    SERVER_ERROR = "server_error"


@dataclass(frozen=True, slots=True)
class VerificationMethod:
    """Curated verification recipe for one vulnerability type.

    ``default_n`` is the number of independent reproductions required for an N/N
    confirmation (e.g. SQLi timing N=5, RCE echo N=3). ``server_error_threshold``
    is the count of consecutive 5xx-driven INCONCLUSIVE results that escalates a
    verification to human review instead of REFUTED. ``oob_window_seconds`` is the
    callback wait window for out-of-band methods (0 = not OOB-based).
    """

    vuln_type: VulnType
    default_n: int
    retry_strategy: RetryStrategy = RetryStrategy.CROSS_WORKER
    cross_worker: bool = True
    server_error_threshold: int = 2
    oob_window_seconds: int = 0

    def __post_init__(self) -> None:
        if self.default_n < 1:
            raise DomainValidationError("VerificationMethod.default_n must be >= 1")
        if self.server_error_threshold < 1:
            raise DomainValidationError(
                "VerificationMethod.server_error_threshold must be >= 1"
            )
        if self.oob_window_seconds < 0:
            raise DomainValidationError(
                "VerificationMethod.oob_window_seconds must be >= 0"
            )


@dataclass(frozen=True, slots=True)
class CandidateFinding:
    """An Observation promoted to a verification candidate (status PENDING)."""

    id: str
    observation_id: str
    vuln_type: VulnType
    target: str
    status: VerificationStatus = VerificationStatus.PENDING

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError("CandidateFinding.id must be non-empty")
        if not self.observation_id:
            raise DomainValidationError(
                "CandidateFinding.observation_id must be non-empty"
            )
        if not self.target:
            raise DomainValidationError("CandidateFinding.target must be non-empty")


@dataclass(frozen=True, slots=True)
class ConfirmedFinding:
    """A candidate the oracle confirmed via N/N independent reproduction."""

    candidate_id: str
    vuln_type: VulnType
    evidence_ids: tuple[str, ...]
    verified_at: datetime
    successes: int
    attempts: int

    def __post_init__(self) -> None:
        if not self.candidate_id:
            raise DomainValidationError("ConfirmedFinding.candidate_id must be non-empty")
        if self.successes < 1:
            raise DomainValidationError("ConfirmedFinding.successes must be >= 1")
        if self.attempts < self.successes:
            raise DomainValidationError(
                "ConfirmedFinding.attempts must be >= successes"
            )


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Aggregated outcome of one verification run."""

    status: VerificationStatus
    successes: int
    attempts: int
    reason: str = ""

    def __post_init__(self) -> None:
        if self.successes < 0 or self.attempts < 0:
            raise DomainValidationError("VerificationResult counts must be >= 0")
        if self.successes > self.attempts:
            raise DomainValidationError(
                "VerificationResult.successes cannot exceed attempts"
            )


def decide_outcome(
    method: VerificationMethod,
    *,
    successes: int,
    attempts: int,
    inconclusive_count: int = 0,
) -> VerificationStatus:
    """Deterministically decide the N/N verification outcome.

    - ``successes >= N``                      -> CONFIRMED
    - attempts exhausted (``attempts >= N``):
        - ``inconclusive_count >= threshold`` -> INCONCLUSIVE (escalate to human)
        - otherwise                           -> REFUTED
    - not enough attempts yet                 -> PENDING

    ``inconclusive_count`` counts server-error (5xx) reproductions, which must
    not be counted as REFUTED - a flaky target is inconclusive, not disproven.
    """
    if successes >= method.default_n:
        return VerificationStatus.CONFIRMED
    if attempts >= method.default_n:
        if inconclusive_count >= method.server_error_threshold:
            return VerificationStatus.INCONCLUSIVE
        return VerificationStatus.REFUTED
    return VerificationStatus.PENDING
