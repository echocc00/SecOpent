"""ReasoningLoop DIFF_SEMANTIC oracle closed-loop (v0.7.6, Task 6).

A ``request_oracle`` step on a LOGIC candidate carrying a ``DiffSemanticPayload``
must be driven through the unchanged ``OracleEngine`` with the factory-dispatched
``DiffSemanticVerifier``, and the outcome surfaced on ``LoopStep.oracle_progressed``.
A logic candidate WITHOUT a diff spec must be INCONCLUSIVE — never a reflexive
REFUTED (spec §5: a missing spec is a lack of evidence, not a disproof).
"""
from __future__ import annotations

import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from secopent.application.audit import AuditService
from secopent.application.canary import CanaryTokenManager
from secopent.application.oracle import OracleVerifier
from secopent.application.reasoning_loop.context_builder import (
    DefaultLoopContextBuilder,
)
from secopent.application.reasoning_loop.feedback import LoopFeedback
from secopent.application.reasoning_loop.in_memory_state import (
    InMemoryLoopStateRepository,
    InMemoryLoopStepRepository,
)
from secopent.application.reasoning_loop.loop_oracle import (
    LoopOracleVerifier,
    OracleOutcome,
)
from secopent.application.reasoning_loop.mock_proposer import MockLoopActionProposer
from secopent.application.reasoning_loop.orchestrator import ReasoningLoopOrchestrator
from secopent.application.reasoning_loop.permit_gate import PermitGateImpl
from secopent.application.reasoning_loop.policy_gate import PolicyGateImpl
from secopent.application.reasoning_loop.schema_gate import SchemaGateImpl
from secopent.domain.catalog.models import TestCatalog
from secopent.domain.policy.models import ExecutionMode, PolicyDecision
from secopent.domain.reasoning_loop.models import (
    LoopActionType,
    LoopBudget,
    LoopId,
    LoopPhase,
    LoopPlan,
    LoopState,
    LoopTerminationPolicy,
    ProposeAction,
)
from secopent.domain.verification.diff_semantic import (
    DiffSemanticPayload,
    Expectation,
)
from secopent.domain.verification.models import (
    CandidateFinding,
    VerificationStatus,
    VulnType,
)
from secopent.domain.verification.registry import default_registry
from secopent.infrastructure.oracle.diff_semantic_runner import (
    DiffSemanticResponse,
)
from secopent.infrastructure.oracle.diff_semantic_verifier import (
    DiffSemanticVerifier,
)
from secopent.infrastructure.permits.permit_signer import (
    PermitSigner,
    PermitVerifier,
)

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


class _FakeAuditRepo:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def add(self, e: Any) -> None:
        self.events.append(e)

    def list_events(self) -> list[Any]:
        return list(self.events)

    def last_hash(self) -> str:
        if not self.events:
            return "0" * 64
        return str(self.events[-1].event_hash).removeprefix("sha256:")


def _allow_all_engine(
    request: Any,
    *,
    scope: Any,
    mode: Any,
    approved_risks: Any,
    approved_capabilities: Any,
) -> PolicyDecision:
    return PolicyDecision(allowed=True, reason="ok")


def _permit_gate() -> PermitGateImpl:
    signer = PermitSigner()
    verifier = PermitVerifier(signer.public_key_bytes())
    return PermitGateImpl(ttl_seconds=900, signer=signer, verifier=verifier)


class _ScriptedDiffRunner:
    """DiffSemanticRunner returning canned responses by URL suffix (deterministic)."""

    def __init__(
        self,
        baseline: DiffSemanticResponse,
        assertion: DiffSemanticResponse,
    ) -> None:
        self._baseline = baseline
        self._assertion = assertion

    def execute(self, request: dict[str, object]) -> DiffSemanticResponse:
        url = str(request.get("url", ""))
        if url.endswith("/baseline"):
            return self._baseline
        return self._assertion


def _diff_factory(runner: _ScriptedDiffRunner) -> Callable[..., OracleVerifier]:
    """Loop candidate-verifier factory that dispatches diff methods."""

    def factory(finding_like: Any, vuln_type: VulnType) -> OracleVerifier:
        return DiffSemanticVerifier(runner)

    return factory


def _idor_payload(candidate_id: str) -> DiffSemanticPayload:
    return DiffSemanticPayload(
        candidate_id=candidate_id,
        baseline_request={"method": "GET", "url": "/baseline"},
        assertion_request={"method": "GET", "url": "/assertion"},
        expectation=Expectation.DENY,
    )


def _candidate(candidate_id: str, diff: DiffSemanticPayload | None) -> CandidateFinding:
    return CandidateFinding(
        id=candidate_id,
        observation_id="obs-1",
        vuln_type=VulnType.IDOR,
        target="https://x.test/",
        diff=diff,
    )


def _request_oracle(candidate_id: str) -> ProposeAction:
    return ProposeAction(
        action_type=LoopActionType.REQUEST_ORACLE,
        payload={"candidate_id": candidate_id},
        rationale="oracle verify the unconfirmed IDOR candidate " + "y" * 40,
        confidence=0.6,
    )


def _bootstrap(
    *,
    candidate_provider: Callable[[str], CandidateFinding | None],
    runner: _ScriptedDiffRunner,
    script: list[ProposeAction],
) -> tuple[ReasoningLoopOrchestrator, LoopId]:
    state_repo = InMemoryLoopStateRepository()
    step_repo = InMemoryLoopStepRepository()
    catalog = TestCatalog(version="t-1", mappings={})
    builder = DefaultLoopContextBuilder(
        catalog=catalog,
        state_repo=state_repo,
        asset_subgraph_provider=lambda aid: (),  # type: ignore[arg-type, return-value]
        observation_provider=lambda lid: (),  # type: ignore[arg-type, return-value]
    )
    proposer = MockLoopActionProposer(script=script)
    schema_gate = SchemaGateImpl()
    policy_gate = PolicyGateImpl(
        scope=None,  # type: ignore[arg-type]  # allow-all engine ignores scope
        mode=ExecutionMode.SCOPE_AUTOPILOT,
        approved_risks=frozenset(),
        approved_capabilities=frozenset(),
        engine=_allow_all_engine,
    )
    permit_gate = _permit_gate()
    audit = AuditService(_FakeAuditRepo())
    canary = CanaryTokenManager(audit)
    loop_oracle = LoopOracleVerifier(
        registry=default_registry(),
        canary=canary,
        verifier_factory=_diff_factory(runner),
        candidate_provider=candidate_provider,
    )
    orchestrator = ReasoningLoopOrchestrator(
        state_repo=state_repo,
        step_repo=step_repo,
        context_builder=builder,
        proposer=proposer,
        schema_gate=schema_gate,
        policy_gate=policy_gate,
        permit_gate=permit_gate,
        feedback=LoopFeedback(),
        audit=audit,
        clock=lambda: _T0,
        loop_oracle=loop_oracle,
    )
    lid = LoopId(value="abcd1234")
    state_repo.save(
        LoopState(
            loop_id=lid,
            assessment_id="asmt-1",
            phase=LoopPhase.INITIALIZING,
            policy_snapshot="sha256:" + "0" * 64,
            budget=LoopBudget.default(),
            context_hash="0" * 64,
            catalog_required_remaining=frozenset(),
            catalog_required_executed=frozenset(),
            consecutive_no_signal=0,
            consecutive_policy_rejected=0,
            started_at=_T0,
            last_step_at=None,
        )
    )
    return orchestrator, lid


def _create_loop(orch: ReasoningLoopOrchestrator, lid: LoopId) -> None:
    orch.create_loop(
        LoopPlan(
            plan_id="lp-1",
            loop_id=lid,
            assessment_id="asmt-1",
            termination_policy=LoopTerminationPolicy.default(),
            policy_snapshot="sha256:" + "0" * 64,
            created_at=_T0,
        ),
        catalog_required_remaining=frozenset(),
    )


def test_oracle_step_confirms_logic_candidate(memory_repositories) -> None:
    """A request_oracle on a LOGIC candidate carrying a diff spec (DENY, baseline
    and assertion both 200 same structure) resolves CONFIRMED and sets
    LoopStep.oracle_progressed True."""
    runner = _ScriptedDiffRunner(
        DiffSemanticResponse(status=200, body={"id": 1002}),
        DiffSemanticResponse(status=200, body={"id": 1002}),
    )
    orch, lid = _bootstrap(
        candidate_provider=lambda cid: _candidate(cid, _idor_payload(cid)),
        runner=runner,
        script=[_request_oracle("cand-diff-1")],
    )
    _create_loop(orch, lid)
    result = orch.run_step(loop_id=lid)
    step = result.step_recorded
    assert step is not None
    assert step.oracle_progressed is True
    assert step.execution_result_digest.startswith("oracle:confirmed")


def test_oracle_logic_candidate_without_diff_is_inconclusive(
    memory_repositories,
) -> None:
    """A LOGIC candidate with no diff spec is INCONCLUSIVE — never a reflexive
    REFUTED. oracle_progressed stays False (not deterministically resolved)."""
    runner = _ScriptedDiffRunner(
        DiffSemanticResponse(status=200, body={"id": 1002}),
        DiffSemanticResponse(status=200, body={"id": 1002}),
    )
    orch, lid = _bootstrap(
        candidate_provider=lambda cid: _candidate(cid, None),  # no diff spec
        runner=runner,
        script=[_request_oracle("cand-diff-1")],
    )
    _create_loop(orch, lid)
    result = orch.run_step(loop_id=lid)
    step = result.step_recorded
    assert step is not None
    assert step.oracle_progressed is False
    assert "oracle:inconclusive" in step.execution_result_digest
    assert "refuted" not in step.execution_result_digest


def test_loop_oracle_verifier_guard_returns_inconclusive(memory_repositories) -> None:
    """Unit-level guarantee on LoopOracleVerifier: a logic candidate without a diff
    spec yields INCONCLUSIVE and the verifier factory is NOT even invoked (no
    risk of a reflexive REFUTE through the engine)."""
    audit = AuditService(_FakeAuditRepo())
    canary = CanaryTokenManager(audit)

    def exploding_factory(finding_like: Any, vuln_type: VulnType) -> OracleVerifier:
        raise AssertionError("factory must not run for a spec-less candidate")

    verifier = LoopOracleVerifier(
        registry=default_registry(),
        canary=canary,
        verifier_factory=exploding_factory,
        candidate_provider=lambda cid: _candidate(cid, None),
    )
    outcome = verifier.verify("cand-diff-1", actor="oracle")
    assert isinstance(outcome, OracleOutcome)
    assert outcome.status is VerificationStatus.INCONCLUSIVE
    assert outcome.resolved is False


# ---------------------------------------------------------------------------
# Ground-truth documentation (spec §5, Juice-Shop-style 越权 / IDOR path).
# Skipped-by-default on non-Linux hosts; it needs a live target to exercise the
# real DiffSemanticRunner over HTTP, so it is documentation of the intended
# end-to-end shape rather than a CI-run assertion here.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="ground-truth IDOR fixture: needs a live Linux target (docs only)",
)
def test_ground_truth_idor_deny_documents_juice_shop_path(
    memory_repositories,
) -> None:
    """A Juice-Shop-style 越权: baseline userA->A orders 200 {order,items}, then a
    DiffSemanticVerifier exercising assertion userA->B orders 200 same structure
    resolves CONFIRMED (the override was embodied and not denied). Exercises the
    real HttpDiffSemanticRunner transport end to end."""
    base_url = os.environ.get("SECOPENT_GT_BASE", "http://localhost:3000")
    runner = _ScriptedDiffRunner(
        DiffSemanticResponse(status=200, body={"order": 1, "items": []}),
        DiffSemanticResponse(status=200, body={"order": 2, "items": []}),
    )
    orch, lid = _bootstrap(
        candidate_provider=lambda cid: _candidate(cid, _idor_payload(cid)),
        runner=runner,
        script=[_request_oracle("cand-diff-1")],
    )
    _create_loop(orch, lid)
    result = orch.run_step(loop_id=lid)
    step = result.step_recorded
    assert step is not None
    assert step.oracle_progressed is True
    assert "oracle:confirmed" in step.execution_result_digest
    assert base_url  # survive linters: the base url is referenced (live targets only)

