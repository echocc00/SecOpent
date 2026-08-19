# src/secopent/application/ports/loop_approval.py
"""Human-only approval gate for loop pause/resume (spec §6.3, v0.7.7)."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ...domain.common.errors import DomainError


class ApprovalRequired(DomainError):
    """A loop resume/action requires a human approval signature."""


class ApprovalRejected(DomainError):
    """Pause/resume requires a human signature; agents are rejected (403)."""


def validate_loop_approval_params(
    *,
    actor_role: str,
    approved_by: str | None,
    signature: str | None,
) -> None:
    """Apply the human-only + signer-presence rules shared by all approval impls.

    Infrastructure implementations call this before/instead of crypto so the
    human-only contract is testable without a real signer:
      - ``actor_role == "agent"`` -> :class:`ApprovalRejected` (403).
      - an empty ``approved_by`` or ``signature`` -> :class:`ApprovalRequired`.

    Actual signature verification (a signed token binding loop_id + actor +
    action + nonce + expiry against the rotating signing keys) is left to the
    concrete infrastructure implementation.
    """
    if actor_role == "agent":
        raise ApprovalRejected("pause/resume is human-only (403): agents are rejected")
    if not approved_by or not signature:
        raise ApprovalRequired("a human approval requires approved_by and signature")


@runtime_checkable
class LoopApproval(Protocol):
    """Validates a human-signed approval for a loop action (resume).

    Aligns with ``assessment.approve`` (approved_by + signature). The concrete
    impl in infrastructure verifies a signed token binding loop_id + actor +
    action + nonce + expiry against the rotating signing keys. This port defines
    the contract + the human-only rule.
    """

    def require_resume_approval(
        self,
        *,
        loop_id: object,
        actor: str,
        actor_role: str,
        approved_by: str | None = None,
        signature: str | None = None,
        nonce: str | None = None,
        expires_at: object | None = None,
    ) -> None:
        """Raise ApprovalRequired/ApprovalRejected when not a valid human resume."""
