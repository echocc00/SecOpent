# tests/infrastructure/reasoning_loop/test_loop_approval.py
"""SignedLoopApproval — human-only resume approval gate (v0.7.7 Task 5).

Asserts the production LoopApproval impl: it applies the shared human-only +
signer-presence rules (agent -> ApprovalRejected; missing signer -> Approval
Required) and accepts a non-empty signature as sufficient (documented stub).
"""
from __future__ import annotations

import pytest

from secopent.application.ports.loop_approval import (
    ApprovalRejected,
    ApprovalRequired,
)
from secopent.domain.reasoning_loop.models import LoopId
from secopent.infrastructure.reasoning_loop.loop_approval import (
    SignedLoopApproval,
)


def _approval() -> SignedLoopApproval:
    return SignedLoopApproval()


def test_agent_rejected() -> None:
    with pytest.raises(ApprovalRejected):
        _approval().require_resume_approval(
            loop_id=LoopId.new(), actor="agent-1", actor_role="agent",
            approved_by="cara", signature="sig",
        )


def test_missing_signer_raises_approval_required() -> None:
    approval = _approval()
    with pytest.raises(ApprovalRequired):
        approval.require_resume_approval(
            loop_id=LoopId.new(), actor="alice", actor_role="human",
        )
    with pytest.raises(ApprovalRequired):
        approval.require_resume_approval(
            loop_id=LoopId.new(), actor="alice", actor_role="human",
            approved_by="bob",
        )


def test_nonempty_signature_accepted_stub() -> None:
    # Stub: any non-empty signature passes (signer-backed check is v0.7.8/9).
    _approval().require_resume_approval(
        loop_id=LoopId.new(), actor="alice", actor_role="human",
        approved_by="bob", signature="sig-123",
    )
