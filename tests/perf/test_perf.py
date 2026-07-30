# tests/perf/test_perf.py
"""Performance regression benchmarks (§3.5 guard / T12 / cross-cutting §⑧).

Opt-in: ``pytest -m perf`` (deselected by default). Each benchmark targets a
§3.5 performance property so a regression is caught continuously rather than
rediscovered late:

1. findings correlation of 1000 observations
2. ExecutionPlan DAG construction with 50 dependent steps
3. audit hash-chain verify over 10000 events
4. intel FTS5 keyword search over a seeded store
5. AdapterStepRunner/Orchestrator concurrency across 3 workers (T4)

Uses pytest-benchmark. Compare runs against ``benchmarks/baseline.json``
(``scripts/check_perf.py``) - CI warns on a > 20% regression.
"""
from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from secopent.application.audit_chain import AuditChain
from secopent.application.finding_correlation import FindingCorrelation
from secopent.application.jobs import JobService
from secopent.application.orchestrator import Orchestrator, StepResult
from secopent.domain.adapters.contracts import (
    AdapterSource,
    CoverageDomain,
    Observation,
    Severity,
)
from secopent.domain.assessments.models import ExecutionPlan, PlanStep
from secopent.domain.common.canonical import utc_now
from secopent.domain.intel.models import (
    AffectedProduct,
    DetectionMapping,
    ExploitationSignal,
    Vulnerability,
)
from secopent.domain.intel.provenance import Provenance
from secopent.domain.jobs.models import JobStatus
from secopent.domain.policy.models import RiskClass
from secopent.infrastructure.db.session import init_db
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_intel import (
    SqlAlchemyIntelRepository,
)

pytestmark = pytest.mark.perf

_T0 = datetime(2026, 1, 1, tzinfo=UTC)
_SOURCE = AdapterSource(name="nuclei", version="1.0.0", template_version="1.0.0")


def _obs(i: int) -> Observation:
    return Observation(
        external_id=f"o{i}",
        asset_identity=f"http://host{i % 50}:3000",
        source=_SOURCE,
        rule_id=f"rule-{i % 25}",
        rule_version="1.0.0",
        coverage_domain=CoverageDomain.WEB,
        title=f"Finding {i}",
        severity=Severity.HIGH,
        confidence=0.9,
        cwe=(f"CWE-{79 + (i % 5)}",),
        owasp=("A03:2021",),
    )


# --- 1. findings correlation of 1000 observations ---------------------------


def test_findings_correlate_1000(benchmark) -> None:  # type: ignore[no-untyped-def]
    observations = [_obs(i) for i in range(1000)]
    correlator = FindingCorrelation()
    findings = benchmark(lambda: correlator.correlate(observations))
    assert findings


# --- 2. ExecutionPlan DAG with 50 dependent steps ---------------------------


def test_plan_dag_50_nodes(benchmark) -> None:  # type: ignore[no-untyped-def]
    steps = tuple(
        PlanStep(
            key=f"s{i}",
            runner="nuclei",
            risk=RiskClass.ACTIVE,
            parameters={},
            dependencies=(f"s{i - 1}",) if i else (),
        )
        for i in range(50)
    )
    plan = benchmark(
        lambda: ExecutionPlan.create(
            plan_id="p", assessment_id="a", version=1, steps=steps
        )
    )
    assert len(plan.steps) == 50


# --- 3. audit hash-chain verify over 10000 events ---------------------------


class _NullSigner:
    def sign(self, message: bytes) -> str:
        return "sig"

    def verify(self, message: bytes, signature: str) -> bool:
        return True


def test_audit_chain_verify_10000(benchmark) -> None:  # type: ignore[no-untyped-def]
    chain = AuditChain(_NullSigner())
    for i in range(10000):
        chain.record(
            actor="a", action="x", resource_type="t", resource_id=f"r{i}", payload={}
        )
    assert benchmark.pedantic(chain.verify, rounds=10, iterations=1) is True


# --- 4. intel FTS5 keyword search over a seeded store -----------------------


def _provenance(source: str = "osv") -> Provenance:
    return Provenance(source=source, fetched_at=utc_now(), source_version="1.0")


def _vulnerability(canonical_id: str, description: str, cwe: str) -> Vulnerability:
    product = AffectedProduct(
        vendor="acme", product="widget", cpe=None, package=None,
        version_range=">=1.0,<2.0", fixed_versions=("2.0.1",),
    )
    mapping = DetectionMapping(
        vulnerability_id=canonical_id, case_version="2026.07",
        detection_type="network", risk=RiskClass.LOW, confidence=0.8,
    )
    signal = ExploitationSignal(
        kev=False, epss_score=0.1, public_exploit=False,
        ransomware=False, active_exploitation=False,
    )
    return Vulnerability(
        canonical_id=canonical_id, aliases=(canonical_id,), description=description,
        cvss={"nvd": (7.5, _provenance("nvd"))}, cwe=(cwe,),
        references=("https://example.org/advisory",),
        published_at=datetime(2024, 6, 1, tzinfo=UTC),
        affected_products=(product,), exploitation_signal=signal,
        detection_mappings=(mapping,), provenance=_provenance("osv"),
    )


def test_intel_fts5_search(benchmark, tmp_path) -> None:  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "intel.db")
    init_db(engine)
    session = Session(engine)
    repo = SqlAlchemyIntelRepository(session)
    for i in range(500):
        repo.add_vulnerability(
            _vulnerability(f"CVE-2024-{i}", f"heap overflow in widget {i}", "CWE-787")
        )
    session.commit()
    try:
        results = benchmark(lambda: repo.search_fts(keyword="widget"))
        assert results
    finally:
        session.close()
        engine.dispose()


# --- 5. AdapterStepRunner / Orchestrator concurrency across 3 workers (T4) ---


class _SleepRunner:
    """Simulates adapter latency so the parallel speedup is measurable."""

    def __init__(self, seconds: float) -> None:
        self._seconds = seconds

    def run(self, step: PlanStep) -> StepResult:
        time.sleep(self._seconds)
        return StepResult(result_digest="sha256:" + "d" * 64)


def _independent_plan(n: int) -> ExecutionPlan:
    steps = tuple(
        PlanStep(key=f"s{i}", runner="nuclei", risk=RiskClass.ACTIVE,
                 parameters={}, dependencies=())
        for i in range(n)
    )
    return ExecutionPlan.create(plan_id="p", assessment_id="a", version=1, steps=steps)


def test_orchestrator_concurrency_3_workers(benchmark) -> None:  # type: ignore[no-untyped-def]
    def run_parallel() -> JobService:
        jobs = JobService()
        orch = Orchestrator(jobs, _SleepRunner(0.03), max_workers=3)
        orch.dispatch(_independent_plan(3))
        orch.execute_ready(owner="w", now=_T0)
        return jobs

    jobs = benchmark.pedantic(run_parallel, rounds=10, iterations=1)
    assert all(job.status is JobStatus.SUCCEEDED for job in jobs.all())
