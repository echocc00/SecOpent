# tests/e2e_real/test_reasoning_loop_ab_mock.py
"""Mock-LLM A/B flow for the ReasoningLoop harness (v0.7.9 Task 2).

A no-cost, deterministic A/B acceptance run comparing the two execution arms on
a live target (default Juice Shop):

- **control** (``_run_catalog_floor``): the deterministic catalog floor —
  ``RealScanRunner`` + a nuclei template driven through ``AdapterStepRunner``,
  returning the observations/candidates it surfaced.
- **experiment** (``_run_reasoning_loop``): the same floor plus
  ``ReasoningLoopOrchestrator`` + ``MockLoopActionProposer`` + ``OracleEngine``
  (with ``DiffSemanticVerifier`` for the logic candidates, ``default_registry()``
  supplying the N/N config). The mock proposer means *no LLM is invoked and no
  tokens are spent* — the only live traffic is the DIFF_SEMANTIC oracle's
  baseline/assertion requests against the target.

The report is written to ``test-results/reasoning_loop_ab.json``. Following the
established ``strix_ab`` house pattern, the test never hard-asserts value
numbers (delta / FP-rate / cost) — A/B is a HUMAN decision gate (spec §14.3) —
it only asserts the report file exists and the process completed.

SKIP CONDITIONS (auto): Docker is absent (skipif) or the target is unreachable
(``require_target``), so this never runs/fails in the default suite.
"""
from __future__ import annotations

import datetime
import json
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which("docker") is None,
        reason="docker unavailable (reasoning loop A/B harness)",
    ),
]

# Fixed 8-hex LoopId valid per the domain's LoopId rules.
_LOOP_ID = "ab9f0011"
_JUICE_URL = "http://localhost:3000"

# Nuclei template for the deterministic catalog floor (control arm): the same
# Juice Shop login SQLi probe used by test_four_domain.py.
_JUICE_SQLI_TEMPLATE = """\
id: juice-shop-login-sqli
info:
  name: Juice Shop login SQLi bypass
  author: secopent
  severity: high
  tags: sqli,sql-injection
http:
  - method: POST
    path:
      - "{{BaseURL}}/rest/user/login"
    headers:
      Content-Type: application/json
    body: |
      {"email":"' OR 1=1--","password":"x"}
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "token"
        part: body
"""


@dataclass(frozen=True, slots=True)
class _LoopSummary:
    """Aggregated, value-neutral outcome of one experiment (loop) arm."""

    oracle_confirmed: int
    refuted: int
    candidates: int
    wall_seconds: float
    tokens_used: int
    approval_count: int
    steps_run: int
    final_phase: str


# ---------------------------------------------------------------------------
# Report writing
# ---------------------------------------------------------------------------

_REPORT_PATH = Path("test-results") / "reasoning_loop_ab.json"


def _write_ab_report(payload: dict) -> str:
    """Write the A/B report JSON, creating parents, and return the path string."""
    _REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _REPORT_PATH.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return str(_REPORT_PATH)


# ---------------------------------------------------------------------------
# Orchestrator / oracle composition (mirrors test_loop_oracle, local copies)
# ---------------------------------------------------------------------------

class _FakeAuditRepo:
    def __init__(self) -> None:
        self.events: list = []

    def add(self, e: object) -> None:  # noqa: ARG002
        self.events.append(e)

    def list_events(self) -> list:
        return list(self.events)

    def last_hash(self) -> str:
        if not self.events:
            return "0" * 64
        return str(self.events[-1].event_hash).removeprefix("sha256:")


def _allow_all_engine(request: object, **_: object):  # noqa: ANN001
    from secopent.domain.policy.models import PolicyDecision

    return PolicyDecision(allowed=True, reason="ok")


def _make_audit_service():  # type: ignore[no-untyped-def]
    from secopent.application.audit import AuditService

    return AuditService(_FakeAuditRepo())


def _candidate(candidate_id: str, baseline: str, assertion: str) -> object:
    """A LOGIC (IDOR) candidate carrying a real DIFF_SEMANTIC payload."""
    from secopent.domain.verification.diff_semantic import (
        DiffSemanticPayload,
        Expectation,
    )
    from secopent.domain.verification.models import CandidateFinding, VulnType

    return CandidateFinding(
        id=candidate_id,
        observation_id="obs-1",
        vuln_type=VulnType.IDOR,
        target=_JUICE_URL,
        diff=DiffSemanticPayload(
            candidate_id=candidate_id,
            baseline_request={"method": "GET", "url": baseline},
            assertion_request={"method": "GET", "url": assertion},
            expectation=Expectation.DENY,
        ),
    )


def _build_loop(
    *,
    audit,  # type: ignore[no-untyped-def]
    candidates: dict[str, object],
    script,  # type: ignore[no-untyped-def]
) -> object:
    """Compose a ReasoningLoopOrchestrator wired to the real DIFF_SEMANTIC oracle."""
    from secopent.application.canary import CanaryTokenManager
    from secopent.application.reasoning_loop.context_builder import (
        DefaultLoopContextBuilder,
    )
    from secopent.application.reasoning_loop.feedback import LoopFeedback
    from secopent.application.reasoning_loop.in_memory_state import (
        InMemoryLoopStateRepository,
        InMemoryLoopStepRepository,
    )
    from secopent.application.reasoning_loop.loop_oracle import LoopOracleVerifier
    from secopent.application.reasoning_loop.mock_proposer import MockLoopActionProposer
    from secopent.application.reasoning_loop.orchestrator import ReasoningLoopOrchestrator
    from secopent.application.reasoning_loop.permit_gate import PermitGateImpl
    from secopent.application.reasoning_loop.policy_gate import PolicyGateImpl
    from secopent.application.reasoning_loop.schema_gate import SchemaGateImpl
    from secopent.domain.catalog.models import TestCatalog
    from secopent.domain.policy.models import ExecutionMode
    from secopent.domain.reasoning_loop.models import AvailableCapability
    from secopent.domain.verification.registry import default_registry
    from secopent.infrastructure.oracle.diff_semantic_runner import (
        HttpDiffSemanticRunner,
    )
    from secopent.infrastructure.oracle.diff_semantic_verifier import (
        DiffSemanticVerifier,
    )
    from secopent.infrastructure.permits.permit_signer import (
        PermitSigner,
        PermitVerifier,
    )

    state_repo = InMemoryLoopStateRepository()
    step_repo = InMemoryLoopStepRepository()
    catalog = TestCatalog(version="ab-mock", mappings={})

    def _tool_capabilities(assessment_id: str) -> tuple:
        return (
            AvailableCapability(
                capability_id="nuclei",
                kind="tool",
                summary="template-driven web/API vulnerability scanner",
                risk_class="active",
                cwe=("CWE-89", "CWE-79"),
            ),
        )

    builder = DefaultLoopContextBuilder(
        catalog=catalog,
        state_repo=state_repo,
        asset_subgraph_provider=lambda aid: (),  # type: ignore[arg-type, return-value]
        observation_provider=lambda lid: (),  # type: ignore[arg-type, return-value]
        tool_provider=_tool_capabilities,
    )
    proposer = MockLoopActionProposer(script=script)
    signer = PermitSigner()
    verifier = PermitVerifier(signer.public_key_bytes())

    def _verifier_factory(finding_like: object, vuln_type: object) -> DiffSemanticVerifier:
        # The experiment's logic candidates are exercised through the real
        # DiffSemanticVerifier transport (baseline/assertion over HTTP). N/N
        # config comes from default_registry() (the rescan branch is not hit by
        # this mock script, which only requests oracle on LOGIC candidates).
        return DiffSemanticVerifier(HttpDiffSemanticRunner(timeout=10))

    loop_oracle = LoopOracleVerifier(
        registry=default_registry(),
        canary=CanaryTokenManager(audit),
        verifier_factory=_verifier_factory,
        candidate_provider=lambda cid: candidates.get(cid),
    )
    orchestrator = ReasoningLoopOrchestrator(
        state_repo=state_repo,
        step_repo=step_repo,
        context_builder=builder,
        proposer=proposer,
        schema_gate=SchemaGateImpl(),
        policy_gate=PolicyGateImpl(
            scope=None,  # type: ignore[arg-type]
            mode=ExecutionMode.SCOPE_AUTOPILOT,
            approved_risks=frozenset(),
            approved_capabilities=frozenset(),
            engine=_allow_all_engine,
        ),
        permit_gate=PermitGateImpl(ttl_seconds=900, signer=signer, verifier=verifier),
        feedback=LoopFeedback(),
        audit=audit,
        loop_oracle=loop_oracle,
    )
    return orchestrator


# ---------------------------------------------------------------------------
# Control arm: deterministic catalog floor
# ---------------------------------------------------------------------------

def _run_catalog_floor(url: str, docker_mount_dir: Path) -> tuple:
    """Deterministic catalog-only scan (control arm), mirroring test_four_domain."""
    from secopent.domain.assessments.models import ExecutionPlan, PlanStep
    from secopent.domain.policy.models import RiskClass
    from secopent.infrastructure.adapters.real_scan import RealScanRunner
    from secopent.infrastructure.adapters.step_runner import AdapterStepRunner, ScanContext

    tpl_dir = docker_mount_dir / "templates"
    tpl_dir.mkdir(exist_ok=True)
    (tpl_dir / "t.yaml").write_text(_JUICE_SQLI_TEMPLATE, encoding="utf-8")

    plan = ExecutionPlan.create(
        plan_id="ab-floor",
        assessment_id="assess-ab-floor",
        version=1,
        steps=(
            PlanStep(
                key="web:sqli", runner="nuclei", risk=RiskClass.ACTIVE,
                parameters={}, dependencies=(),
            ),
        ),
    )
    step_runner = AdapterStepRunner(
        RealScanRunner(default_timeout=180),
        ScanContext(targets=(url,), template_host_dir=str(tpl_dir)),
    )
    step_runner.run(plan.steps[0])
    observations = step_runner.all_observations()
    candidates = tuple(
        o for o in observations if any("CWE-89" in c for c in o.cwe)
    )
    return observations, candidates


# ---------------------------------------------------------------------------
# Experiment arm: catalog + ReasoningLoop (+ mock proposer + DIFF_SEMANTIC oracle)
# ---------------------------------------------------------------------------

def _run_reasoning_loop(
    url: str,
    docker_mount_dir: Path,  # noqa: ARG001
    proposer: str = "mock",
) -> _LoopSummary:
    """Drive a bounded reasoning loop with a MOCK proposer + DIFF_SEMANTIC oracle."""
    from secopent.domain.reasoning_loop.models import (
        LoopActionType,
        LoopId,
        LoopPhase,
        LoopPlan,
        LoopTerminationPolicy,
        ProposeAction,
    )

    if proposer != "mock":
        raise ValueError(f"only the mock proposer is supported, got {proposer!r}")

    audit = _make_audit_service()

    # Two LOGIC IDOR candidates sharing the Juice Shop orders/promotion surface.
    candidates = {
        "cand-idor-1": _candidate(
            "cand-idor-1",
            f"{url}/rest/user/1/orders",
            f"{url}/rest/user/2/orders",
        ),
        "cand-idor-2": _candidate(
            "cand-idor-2",
            f"{url}/rest/user/1/orders",
            f"{url}/rest/user/2/orders",
        ),
    }
    script = [
        ProposeAction(
            action_type=LoopActionType.RUN_TOOL,
            payload={"tool_id": "nuclei", "parameters": {}},
            rationale="run the catalog floor scan first to seed observations "
            + "x" * 20,
            confidence=0.5,
        ),
        ProposeAction(
            action_type=LoopActionType.REQUEST_ORACLE,
            payload={"candidate_id": "cand-idor-1"},
            rationale="DIFF_SEMANTIC verify the unconfirmed IDOR candidate "
            + "y" * 40,
            confidence=0.6,
        ),
        ProposeAction(
            action_type=LoopActionType.REQUEST_ORACLE,
            payload={"candidate_id": "cand-idor-2"},
            rationale="DIFF_SEMANTIC verify the second unconfirmed IDOR candidate "
            + "z" * 40,
            confidence=0.6,
        ),
    ]
    orchestrator = _build_loop(audit=audit, candidates=candidates, script=script)

    lid = LoopId(value=_LOOP_ID)
    plan = LoopPlan(
        plan_id="lp-ab-mock",
        loop_id=lid,
        assessment_id="assess-ab-mock",
        termination_policy=LoopTerminationPolicy.default(),
        policy_snapshot="sha256:" + "0" * 64,
        created_at=datetime.datetime.now(datetime.UTC),
    )
    orchestrator.create_loop(plan, catalog_required_remaining=frozenset())

    started = time.monotonic()
    steps_run = 0
    tokens_used = 0
    approval_count = 0
    oracle_confirmed = 0
    refuted = 0
    candidates_seen = 0
    final_phase = LoopPhase.RUNNING.value
    # Drive exactly the scripted actions (bounded, deterministic — the mock
    # proposer never runs past its script, so no backend-exhaustion terminal
    # is forced; a terminal break is kept as a safety net for the N/N path).
    for _ in range(len(script)):
        result = orchestrator.run_step(loop_id=lid)
        steps_run += 1
        step = result.step_recorded
        if step is None:
            continue
        tokens_used += step.propose_tokens_used
        if step.permit_id is not None:
            approval_count += 1
        if step.proposed_action.action_type is LoopActionType.REQUEST_ORACLE:
            candidates_seen += 1
            if step.oracle_progressed:
                if "oracle:confirmed" in step.execution_result_digest:
                    oracle_confirmed += 1
                elif "oracle:refuted" in step.execution_result_digest:
                    refuted += 1
        if result.phase is not LoopPhase.RUNNING:
            final_phase = result.phase.value
            break
    wall_seconds = time.monotonic() - started

    return _LoopSummary(
        oracle_confirmed=oracle_confirmed,
        refuted=refuted,
        candidates=candidates_seen,
        wall_seconds=wall_seconds,
        tokens_used=tokens_used,
        approval_count=approval_count,
        steps_run=steps_run,
        final_phase=final_phase,
    )


# ---------------------------------------------------------------------------
# The A/B acceptance test
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_reasoning_loop_ab_mock_flow(
    require_target, docker_mount_dir: Path, record_property
) -> None:  # type: ignore[no-untyped-def]
    """Control vs experiment on live Juice Shop; writes reasoning_loop_ab.json.

    Value numbers are recorded, never hard-asserted (A/B is a human gate).
    """
    url = require_target("juice_shop")

    floor_observations, floor_candidates = _run_catalog_floor(url, docker_mount_dir)
    summary = _run_reasoning_loop(url, docker_mount_dir, proposer="mock")

    report_path = _write_ab_report(
        {
            "date": datetime.date.today().isoformat(),
            "target": url,
            "proposer": "mock",
            "catalog_floor": {
                "observation_count": len(floor_observations),
                "candidate_count": len(floor_candidates),
            },
            "reasoning_loop": {
                "oracle_confirmed": summary.oracle_confirmed,
                "refuted": summary.refuted,
                "candidates": summary.candidates,
                "steps_run": summary.steps_run,
                "tokens_used": summary.tokens_used,
                "approval_count": summary.approval_count,
                "wall_seconds": round(summary.wall_seconds, 3),
                "final_phase": summary.final_phase,
            },
        }
    )
    record_property("reasoning_loop_ab_report", report_path)
    assert Path(report_path).exists()
