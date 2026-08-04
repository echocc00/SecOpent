# src/secopent/domain/permits/models.py
"""ExecutionPermit: a signed, short-lived, single-use authorization (§12).

A worker may only execute a job if it holds a permit that is signed (Ed25519),
short-lived (default 15 min), bound to a specific job/worker/scope/plan, carries
a budget + capabilities, and has a unique nonce (so a captured permit cannot be
replayed). The signature covers every content field, so any tampering invalidates
the permit. Verification (signature / expiry / replay / worker binding) lives in
infrastructure (Ed25519); the errors are declared here so both layers share them.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ..common.canonical import canonical_json
from ..common.errors import DomainError, DomainValidationError

# Default permit lifetime.
DEFAULT_PERMIT_TTL_SECONDS = 15 * 60


class PermitSignatureInvalid(DomainError):
    """The permit signature does not verify (tampered or wrong key)."""


class PermitExpired(DomainError):
    """The permit is past its expires_at."""


class PermitReplayed(DomainError):
    """The permit nonce was already used (replay attempt)."""


class PermitWorkerMismatch(DomainError):
    """The permit is bound to a different worker."""


@dataclass(frozen=True, slots=True)
class ExecutionPermit:
    """A signed authorization for one worker to run one job."""

    job_id: str
    worker_id: str
    scope_digest: str
    plan_digest: str
    capabilities: tuple[str, ...]
    budget: float
    issued_at: datetime
    expires_at: datetime
    nonce: str
    signature: str = ""  # hex-encoded Ed25519 signature

    def __post_init__(self) -> None:
        if not self.job_id:
            raise DomainValidationError("ExecutionPermit.job_id must be non-empty")
        if not self.worker_id:
            raise DomainValidationError("ExecutionPermit.worker_id must be non-empty")
        if not self.nonce:
            raise DomainValidationError("ExecutionPermit.nonce must be non-empty")
        if self.budget < 0:
            raise DomainValidationError("ExecutionPermit.budget must be >= 0")
        if self.expires_at <= self.issued_at:
            raise DomainValidationError(
                "ExecutionPermit.expires_at must be after issued_at"
            )

    def is_expired(self, now: datetime) -> bool:
        """True if ``now`` is at or past the permit's expiry."""
        return now >= self.expires_at

    def signing_payload(self) -> bytes:
        """Canonical bytes over every content field (excludes the signature)."""
        return canonical_json(
            {
                "job_id": self.job_id,
                "worker_id": self.worker_id,
                "scope_digest": self.scope_digest,
                "plan_digest": self.plan_digest,
                "capabilities": self.capabilities,
                "budget": self.budget,
                "issued_at": self.issued_at,
                "expires_at": self.expires_at,
                "nonce": self.nonce,
            }
        ).encode("utf-8")
