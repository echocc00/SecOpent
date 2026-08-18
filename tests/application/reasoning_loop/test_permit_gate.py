"""PermitGate — short-lived, signed, nonce-protected permits (spec §6.3).

Reconciled to existing permit infra: the gate reuses
``domain.permits.models.ExecutionPermit`` + its ``signing_payload()`` flow,
signed via the existing ``PermitSignerProtocol``/``PermitVerifierProtocol``
ports (concrete ``PermitSigner``/``PermitVerifier`` live in infrastructure,
injected here). The application layer adds no crypto.
"""
from __future__ import annotations

from secopent.application.reasoning_loop.permit_gate import PermitGateImpl
from secopent.domain.permits.models import DEFAULT_PERMIT_TTL_SECONDS
from secopent.domain.reasoning_loop.models import (
    LoopActionType,
    LoopBudgetSnapshot,
    LoopContext,
    ProposeAction,
)
from secopent.infrastructure.permits.permit_signer import (
    PermitSigner,
    PermitVerifier,
)


def _ctx() -> LoopContext:
    return LoopContext(
        asset_subgraph=(), recent_observations=(), observation_token_count=0,
        catalog_already_executed=frozenset(), catalog_still_required=frozenset(),
        catalog_floor_progress=0.0, unconfirmed_candidates=(),
        confirmed_findings_recent=(), chain_hypotheses_pending=(),
        available_tools=(), available_cases=(), available_peers=(),
        budget_remaining=LoopBudgetSnapshot(50, 200_000, 1800),
        loop_step=0, max_steps=50, elapsed_seconds=0,
    )


def _action() -> ProposeAction:
    return ProposeAction(
        action_type=LoopActionType.RUN_TOOL,
        payload={"tool_id": "nuclei", "parameters": {}},
        rationale="x" * 80,
        confidence=0.5,
    )


def _gate(ttl_seconds: int = DEFAULT_PERMIT_TTL_SECONDS) -> PermitGateImpl:
    signer = PermitSigner()
    verifier = PermitVerifier(signer.public_key_bytes())
    return PermitGateImpl(ttl_seconds=ttl_seconds, signer=signer, verifier=verifier)


def test_permit_gate_issues_signed_permit_with_ttl() -> None:
    gate = _gate(ttl_seconds=900)
    verdict = gate.check(_action(), _ctx())
    assert verdict.passed is True
    assert verdict.permit_id is not None
    assert verdict.permit_ttl_seconds == 900


def test_permit_gate_permits_are_unique_across_calls() -> None:
    gate = _gate()
    ids = {gate.check(_action(), _ctx()).permit_id for _ in range(50)}
    assert len(ids) == 50  # all unique nonces


def test_permit_gate_signature_verifies() -> None:
    gate = _gate()
    verdict = gate.check(_action(), _ctx())
    assert gate.verify(verdict.permit_id, _action(), _ctx()) is True


def test_permit_gate_tampered_action_fails_verification() -> None:
    gate = _gate()
    verdict = gate.check(_action(), _ctx())
    tampered = _action().model_copy(update={"confidence": 0.99})
    assert gate.verify(verdict.permit_id, tampered, _ctx()) is False
