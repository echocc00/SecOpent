# tests/e2e_real/test_reasoning_loop_ab.py
"""A/B acceptance for the ReasoningLoop with a REAL LLM proposer (v0.7.9 Task 3).

Companion to ``test_reasoning_loop_ab_mock.py`` (Task 2), which runs the same
two arms (deterministic catalog floor vs catalog+ReasoningLoop) with a MOCK
proposer. This file runs the **real** proposer arm through
``create_loop_proposer(mode="real")`` on all three provisioned targets
(Juice Shop / cr_api / vulhub), so the A/B compares the LLM-driven loop against
the deterministic floor under live conditions.

Design notes (resolved, do not re-derive):
- **Token metering**: ``experiment.tokens_used`` accumulates
  ``step.propose_tokens_used`` across the loop's recorded steps — that IS the
  loop's audited per-step token accounting (``LOOP_STEP_PROPOSED`` payload).
  The real backend's actual token cost is surfaced through the loop's audit
  trail, not by wrapping the backend in RemoteModelGateway. This is test-only,
  A/B research output; no production code is touched.
- **Real proposer**: built via ``create_loop_proposer(env=..., config_path=...)``
  with ``SECOPENT_LOOP_PROPOSER=real`` so it uses the config-driven LLM backend
  (or degrades to Mock when the backend is unavailable). A ``BudgetGateImpl``
  caps the run as an A/B safety net.
- **Skip gating (CRITICAL)**: marked ``integration`` + ``peer_real`` and skipped
  when Docker is absent or no LLM key is set, so it NEVER runs/fails in the
  default suite (~2070 passed) and skips in this environment.
- **No hard value asserts**: only the report file's existence is asserted; A/B
  is a human decision gate (spec §14.3).
"""
from __future__ import annotations

import datetime
import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.peer_real,
    pytest.mark.skipif(
        shutil.which("docker") is None
        or (
            not os.environ.get("SECOPENT_PEER_LLM_KEY")
            and not os.environ.get("LLM_API_KEY")
        ),
        reason="docker unavailable or no LLM key (reasoning loop real A/B)",
    ),
]

# Fixed 8-hex LoopId valid per the domain's LoopId rules.
_LOOP_ID = "ab9f0012"

# Bounded steps for the REAL (LLM-driven) proposer arm: the LLM proposes
# actions dynamically, so the loop is driven to a fixed modest step bound and
# stopped early on any terminal phase. The BudgetGateImpl is the hard cap.
_REAL_STEP_BOUND = 8

# Repo-relative LLM backend config consumed by create_loop_proposer.
_LLM_CONFIG = Path("config") / "llm.yaml"

_TARGET_NAMES = ("juice_shop", "cr_api", "vulhub")

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
        target=baseline.split("/rest/")[0],
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
    proposer: object,
    budget_gate: object | None = None,
) -> object:
    """Compose a ReasoningLoopOrchestrator around an injected proposer."""
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
    catalog = TestCatalog(version="ab-real", mappings={})

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
    signer = PermitSigner()
    verifier = PermitVerifier(signer.public_key_bytes())

    def _verifier_factory(finding_like: object, vuln_type: object) -> DiffSemanticVerifier:
        return DiffSemanticVerifier(HttpDiffSemanticRunner(timeout=10))

    loop_oracle = LoopOracleVerifier(
        registry=default_registry(),
        canary=CanaryTokenManager(audit),
        verifier_factory=_verifier_factory,
        candidate_provider=lambda cid: candidates.get(cid),
    )
    return ReasoningLoopOrchestrator(
        state_repo=state_repo,
        step_repo=step_repo,
        context_builder=builder,
        proposer=proposer,  # type: ignore[arg-type]
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
        budget_gate=budget_gate,  # type: ignore[arg-type]
    )


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
# Experiment arm: catalog + ReasoningLoop (mock OR real proposer + oracle)
# ---------------------------------------------------------------------------

def _real_proposer(audit):  # type: ignore[no-untyped-def]
    """Build the config-driven real proposer via create_loop_proposer.

    ``SECOPENT_LOOP_PROPOSER=real`` selects the real mode; if the backend is
    unavailable (no key / bad config) create_loop_proposer degrades to Mock and
    records a ``loop.fallback_used`` audit event — the loop still runs and we
    record whatever actually ran (A/B research output).
    """
    from secopent.infrastructure.reasoning_loop.composition import (
        create_loop_proposer,
    )

    env = dict(os.environ)
    env["SECOPENT_LOOP_PROPOSER"] = "real"
    return create_loop_proposer(
        audit=audit,
        env=env,
        config_path=_LLM_CONFIG,
    )


def _run_reasoning_loop(
    url: str,
    docker_mount_dir: Path,  # noqa: ARG001
    proposer: str = "mock",
) -> _LoopSummary:
    """Drive a bounded reasoning loop with a MOCK or REAL proposer + oracle.

    Token metering (resolved): ``tokens_used`` accumulates
    ``step.propose_tokens_used`` across recorded steps — the loop's audited
    per-step token accounting via ``LOOP_STEP_PROPOSED``. This is test-only A/B
    research output; the real backend's cost is surfaced via the audit trail.
    """
    from secopent.application.reasoning_loop.mock_proposer import MockLoopActionProposer
    from secopent.domain.reasoning_loop.models import (
        LoopActionType,
        LoopBudget,
        LoopId,
        LoopPhase,
        LoopPlan,
        LoopTerminationPolicy,
        ProposeAction,
    )

    if proposer not in ("mock", "real"):
        raise ValueError(f"unsupported proposer {proposer!r} (expected 'mock'|'real')")

    audit = _make_audit_service()

    # Two LOGIC IDOR candidates sharing the orders/promotion surface.
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

    if proposer == "mock":
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
        proposer_impl: object = MockLoopActionProposer(script=script)
        step_bound = len(script)
    else:
        # Real LLM proposer (or degrades to Mock when no usable backend).
        proposer_impl = _real_proposer(audit)
        step_bound = _REAL_STEP_BOUND

    # A/B safety net: hard cumulative token cap so a runaway real-LLM run is
    # bounded. ``consume`` only advances tokens, not steps, so this caps
    # cumulative spend rather than step count (steps are bounded by step_bound).
    budget_gate = None
    if proposer == "real":
        from secopent.application.reasoning_loop.budget_gate import BudgetGateImpl

        budget_gate = BudgetGateImpl(
            budget_now=lambda: LoopBudget(
                max_steps=step_bound,
                max_total_tokens=200_000,
                max_wall_seconds=1800,
            )
        )

    orchestrator = _build_loop(
        audit=audit,
        candidates=candidates,
        proposer=proposer_impl,
        budget_gate=budget_gate,
    )

    lid = LoopId(value=_LOOP_ID)
    plan = LoopPlan(
        plan_id="lp-ab-real",
        loop_id=lid,
        assessment_id="assess-ab-real",
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
    for _ in range(step_bound):
        result = orchestrator.run_step(loop_id=lid)
        steps_run += 1
        step = result.step_recorded
        if step is None:
            if result.phase is not LoopPhase.RUNNING:
                final_phase = result.phase.value
                break
            continue
        # Token metering: accumulate the loop's audited per-step token spend
        # (the value surfaced in the LOOP_STEP_PROPOSED audit payload).
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
# The A/B acceptance test (real proposer; three targets)
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.peer_real
@pytest.mark.skipif(
    shutil.which("docker") is None
    or (
        not os.environ.get("SECOPENT_PEER_LLM_KEY")
        and not os.environ.get("LLM_API_KEY")
    ),
    reason="docker unavailable or no LLM key (reasoning loop real A/B)",
)
def test_reasoning_loop_ab(
    require_target, docker_mount_dir: Path, record_property
) -> None:  # type: ignore[no-untyped-def]
    """Control vs REAL-LLM experiment on all provisioned targets.

    Value numbers are recorded, never hard-asserted (A/B is a human gate).
    """
    results: dict[str, dict] = {}
    for target_name in _TARGET_NAMES:
        url = require_target(target_name)  # skips that target if unreachable
        floor_observations, _floor_candidates = _run_catalog_floor(url, docker_mount_dir)
        experiment = _run_reasoning_loop(url, docker_mount_dir, proposer="real")
        results[target_name] = {
            "control_observations": len(floor_observations),
            "experiment_oracle_confirmed": experiment.oracle_confirmed,
            "experiment_candidates": experiment.candidates,
            "false_positive_rate": (
                (experiment.refuted / experiment.candidates)
                if experiment.candidates
                else 0.0
            ),
            "cost_tokens": experiment.tokens_used,
            "wall_seconds": round(experiment.wall_seconds, 3),
            "approval_count": experiment.approval_count,
        }

    report_path = _write_ab_report(
        {
            "date": datetime.datetime.now(datetime.UTC).isoformat(),
            "proposer": "real",
            "results": results,
        }
    )
    record_property("reasoning_loop_ab", report_path)
    assert Path(report_path).exists()
