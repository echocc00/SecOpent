# src/secopent/infrastructure/reasoning_loop/loop_approval.py
"""Production LoopApproval impl: human-only resume signature gate (spec §6.3).

``SignedLoopApproval`` applies the shared human-only + signer-presence rules via
``validate_loop_approval_params`` (agent -> ApprovalRejected; missing
approved_by/signature -> ApprovalRequired), then treats any non-empty signature
as sufficient for NOW.

This is a documented stub pending the signer-backed implementation (v0.7.8/9):
a real impl binds a signed token over loop_id + actor + action + nonce + expiry
and verifies it against the rotating signing keys (SigningKeyService / Ed25519).
For this task a non-empty signature is accepted as sufficient, which keeps the
human-only contract testable without standing up a full signer.
"""
from __future__ import annotations

from ...application.ports.loop_approval import (
    LoopApproval,
    validate_loop_approval_params,
)


class SignedLoopApproval(LoopApproval):
    """Requires a human actor + non-empty approved_by/signature.

    Signature verification is a stub (documented): any non-empty signature
    passes. v0.7.8/9 will replace the stub with a real signer-backed check.
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
        # Human-only + signer-presence (agent -> ApprovalRejected, missing ->
        # ApprovalRequired). Signature is not (yet) cryptographically verified:
        # a non-empty signature is treated as sufficient (stub, see module doc).
        validate_loop_approval_params(
            actor_role=actor_role,
            approved_by=approved_by,
            signature=signature,
        )
