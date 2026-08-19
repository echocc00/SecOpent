"""Tests for the LoopApproval port — human-only resume gate (spec §6.3).

The signature verification itself lives in infrastructure (mirrors the
``signing_keys`` rotate mechanism). This port defines the contract plus the
testable human-only + signer-presence rules via ``validate_loop_approval_params``.
"""
from __future__ import annotations

import pytest

from secopent.application.ports.loop_approval import (
    ApprovalRejected,
    ApprovalRequired,
    LoopApproval,
    validate_loop_approval_params,
)
from secopent.domain.common.errors import DomainError


class FakeLoopApproval:
    """Concrete fake that satisfies the LoopApproval Protocol.

    Delegates param validation (human-only + signer-presence) to the shared
    helper; in production the infra impl would additionally verify the signed
    token against the rotating signing keys.
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
        validate_loop_approval_params(
            actor_role=actor_role,
            approved_by=approved_by,
            signature=signature,
        )


class TestLoopApprovalHumanOnly:
    def test_approve_requires_signer(self) -> None:
        """Missing approved_by/signature raises ApprovalRequired."""
        approval: LoopApproval = FakeLoopApproval()
        with pytest.raises(ApprovalRequired):
            approval.require_resume_approval(
                loop_id="loop-1",
                actor="op",
                actor_role="human",
                approved_by=None,
                signature=None,
            )
        with pytest.raises(ApprovalRequired):
            approval.require_resume_approval(
                loop_id="loop-1",
                actor="op",
                actor_role="human",
                approved_by="op",
                signature="",
            )

    def test_agent_denied(self) -> None:
        """actor_role == 'agent' raises ApprovalRejected (403 human-only)."""
        approval: LoopApproval = FakeLoopApproval()
        with pytest.raises(ApprovalRejected):
            approval.require_resume_approval(
                loop_id="loop-1",
                actor="agent1",
                actor_role="agent",
                approved_by="op",
                signature="sig",
            )

    def test_valid_human_approval_proceeds(self) -> None:
        """A non-empty human signature does NOT raise (approval proceeds)."""
        approval: LoopApproval = FakeLoopApproval()
        # Should not raise.
        approval.require_resume_approval(
            loop_id="loop-1",
            actor="op",
            actor_role="human",
            approved_by="op",
            signature="sig",
            nonce="n1",
            expires_at=12345,
        )


class TestSharedHelper:
    def test_errors_are_domain_errors(self) -> None:
        """Both errors derive from DomainError (API layer maps consistently)."""
        assert issubclass(ApprovalRequired, DomainError)
        assert issubclass(ApprovalRejected, DomainError)

    def test_helper_agent_role_rejected(self) -> None:
        with pytest.raises(ApprovalRejected):
            validate_loop_approval_params(actor_role="agent", approved_by="x", signature="y")

    def test_helper_missing_signer_required(self) -> None:
        with pytest.raises(ApprovalRequired):
            validate_loop_approval_params(actor_role="human", approved_by="", signature="y")
