"""End-to-end assessment integration test (M4 Task 12, §13 full chain).

Exercises the whole deterministic spine with real components and a mock adapter
backend: Planner builds the DAG from the catalog -> human approval gates the
start -> Orchestrator runs every step to SUCCEEDED in dependency order ->
observations are correlated into findings -> the oracle confirms each at N/N ->
the coverage gate passes (all required classes covered) -> the report renders
data-driven with the completeness gate green. A second test shows the coverage
gate FAILS when a required class is not covered.

Real adapters/targets (Juice Shop/crAPI/httpbin) are M5 E2E; the adapter backend
is mocked here.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

import pytest

from secopent.application.audit import AuditService
from secopent.application.canary import CanaryTokenManager
from secopent.application.coverage import CoverageService
from secopent.application.finding_correlation import FindingCorrelation
from secopent.application.jobs import JobService
from secopent.application.oracle import OracleEngine
from secopent.application.orchestrator import Orchestrator, StepResult
from secopent.application.planner import Planner
from secopent.application.report_renderer import ReportData, ReportRenderer
from secopent.domain.adapters.contracts import (
    AdapterSource,
    CoverageDomain,
    Observation,
    Severity,
)
from secopent.domain.assessments.models import Approval, Assessment
from secopent.domain.audit.models import GENESIS_HASH, AuditEvent
from secopent.domain.catalog.models import AssetType, RequiredTestClass, TestCatalog
from secopent.domain.common.canonical import canonical_digest
from secopent.domain.findings.models import Finding, FindingStatus
from secopent.domain.policy.models import ExecutionMode, RiskClass
from secopent.domain.scope.models import ScopeDraft
from secopent.domain.verification.models import (
    CandidateFinding,
    ConfirmedFinding,
    ReproductionStatus,
    VerificationStatus,
    VulnType,
)
from secopent.domain.verification.registry import default_registry
from secopent.infrastructure.evidence_store.redaction import RedactionEngine
from secopent.infrastructure.report_templates.renderer import Jinja2TemplateRenderer

_T0 = datetime(2026, 1, 1, tzinfo=UTC)
_SOURCE = AdapterSource(name="nuclei", version="3.0.0", template_version="1.0.0")
_CWE_TO_VULN = {"CWE-89": VulnType.SQLI, "CWE-79": VulnType.XSS}


@dataclass
class _MemoryAuditRepo:
    events: list[AuditEvent] = field(default_factory=list)

    def add(self, e: AuditEvent) -> None:
        self.events.append(e)

    def list_events(self) -> list[AuditEvent]:
        return list(self.events)

    def last_hash(self) -> str:
        return self.events[-1].event_hash.removeprefix("sha256:") if self.events else GENESIS_HASH


class EmittingRunner:
    """Mock adapter backend: running a step emits an observation for its CWE."""

    def __init__(self, observations: list[Observation]) -> None:
        self._observations = observations
        self._counter = 0

    def run(self, step) -> StepResult:  # type: ignore[no-untyped-def]
        self._counter += 1
        cwe = tuple(step.parameters.get("cwe", ()))
        test_class = str(step.parameters.get("test_class", "check"))
        self._observations.append(
            Observation(
                external_id=f"obs-{self._counter}",
                asset_identity="https://shop.test/",
                source=_SOURCE,
                rule_id=step.key,
                rule_version="1.0.0",
                coverage_domain=CoverageDomain.WEB,
                title=f"{test_class} finding",
                severity=Severity.HIGH,
                confidence=0.9,
                cwe=cwe,
            )
        )
        return StepResult(result_digest=canonical_digest({"step": step.key}))


class AlwaysSucceedVerifier:
    """Oracle backend that always reproduces successfully (ground-truth vuln)."""

    def reproduce(self, candidate, method, *, canary_token) -> ReproductionStatus:  # type: ignore[no-untyped-def]
        return ReproductionStatus.SUCCESS


def _catalog() -> TestCatalog:
    return TestCatalog(
        version="2026.07",
        mappings={
            AssetType.WEB_APP: (
                RequiredTestClass(
                    id="sqli", cwe=("CWE-89",), owasp=("A03:2021",), risk=RiskClass.ACTIVE
                ),
                RequiredTestClass(
                    id="xss", cwe=("CWE-79",), owasp=("A03:2021",), risk=RiskClass.ACTIVE
                ),
            ),
        },
    )


def _approve(assessment_id: str, plan_digest: str, scope_digest: str) -> Approval:
    return Approval.create(
        approval_id="approval-1",
        assessment_id=assessment_id,
        plan_digest=plan_digest,
        scope_digest=scope_digest,
        mode=ExecutionMode.SCOPE_AUTOPILOT,
        approved_risks=frozenset({RiskClass.PASSIVE, RiskClass.LOW, RiskClass.ACTIVE}),
        approved_capabilities=frozenset({"passive", "network.connect"}),
        approved_by="human-reviewer",
    )


def _verify_findings(
    findings: tuple[Finding, ...],
) -> tuple[list[Finding], list[ConfirmedFinding]]:
    """Confirm each finding at N/N via the oracle and mark it VALIDATED."""
    engine = OracleEngine(
        registry=default_registry(),
        verifier=AlwaysSucceedVerifier(),
        canary=CanaryTokenManager(AuditService(_MemoryAuditRepo())),
    )
    validated: list[Finding] = []
    confirmed: list[ConfirmedFinding] = []
    for finding in findings:
        vuln_type = _CWE_TO_VULN[finding.cwe[0]]
        candidate = CandidateFinding(
            id=finding.id,
            observation_id=finding.observation_ids[0],
            vuln_type=vuln_type,
            target=finding.asset,
        )
        result = engine.verify(candidate, actor="oracle")
        assert result.status is VerificationStatus.CONFIRMED
        confirmed.append(
            engine.confirm(
                candidate, result, evidence_ids=("ev-1",), verified_at=_T0
            )
        )
        validated.append(replace(finding, status=FindingStatus.VALIDATED))
    return validated, confirmed


def test_end_to_end_assessment_happy_path() -> None:
    # 1. Scope + assessment.
    snapshot = ScopeDraft(
        project_id="proj-1", include=("https://shop.test",)
    ).freeze(snapshot_id="scope-1", approved_by="analyst")
    assessment = Assessment.create(
        assessment_id="assess-1",
        project_id="proj-1",
        scope_snapshot_id=snapshot.id,
        mode=ExecutionMode.SCOPE_AUTOPILOT,
    )

    # 2. Planner builds the DAG from the catalog (all required classes).
    catalog = _catalog()
    plan = Planner(catalog).generate(
        plan_id="plan-1", assessment_id=assessment.id, asset_types=[AssetType.WEB_APP]
    )
    assert {s.key for s in plan.steps} == {"web_app:sqli", "web_app:xss"}

    # 3. Human approval gates the start.
    approval = _approve(assessment.id, plan.digest, snapshot.digest)
    started = assessment.start(plan_id=plan.id, approval_id=approval.id)
    assert started.active_plan_id == plan.id

    # 4. Orchestrator runs every step to SUCCEEDED.
    observations: list[Observation] = []
    orchestrator = Orchestrator(JobService(), EmittingRunner(observations))
    orchestrator.dispatch(plan)
    orchestrator.run_to_completion(owner="worker-1", now=_T0)
    from secopent.domain.jobs.models import JobStatus

    jobs = orchestrator._jobs.all()
    assert all(j.status is JobStatus.SUCCEEDED for j in jobs)
    assert len(observations) == 2

    # 5. Correlate observations into findings (cross-tool dedup).
    findings = FindingCorrelation().correlate(observations)
    assert len(findings) == 2

    # 6. Oracle confirms each at N/N -> VALIDATED.
    validated_findings, confirmed = _verify_findings(findings)
    assert len(confirmed) == 2

    # 7. Coverage gate passes (all required classes covered).
    coverage = CoverageService()
    report = coverage.compute(AssetType.WEB_APP, observations, catalog)
    coverage.enforce_gate(report)  # no raise
    assert report.coverage_rate == 1.0

    # 8. Report renders data-driven with the completeness gate green.
    renderer = ReportRenderer(Jinja2TemplateRenderer(), RedactionEngine())
    rendered = renderer.render(
        ReportData(
            assessment_id=assessment.id,
            title="shop.test assessment",
            scope_summary="Authorized test of https://shop.test",
            method="Catalog-driven active assessment.",
            findings=tuple(validated_findings),
            coverage_rate=report.coverage_rate,
            uncovered_classes=report.uncovered_classes,
            evidence_digests=("sha256:" + "e" * 64,),
            assets=("https://shop.test",),
        ),
        report_id="report-1",
    )
    assert rendered.completeness_ok is True
    assert rendered.finding_count == 2


def test_coverage_gate_blocks_incomplete_assessment() -> None:
    catalog = _catalog()
    # Only the sqli observation is produced; xss is never tested.
    observations = [
        Observation(
            external_id="obs-1",
            asset_identity="https://shop.test/",
            source=_SOURCE,
            rule_id="web_app:sqli",
            rule_version="1.0.0",
            coverage_domain=CoverageDomain.WEB,
            title="sqli finding",
            severity=Severity.HIGH,
            confidence=0.9,
            cwe=("CWE-89",),
        )
    ]
    report = CoverageService().compute(AssetType.WEB_APP, observations, catalog)
    from secopent.application.coverage import CoverageGapError

    with pytest.raises(CoverageGapError):
        CoverageService().enforce_gate(report)
    assert "xss" in report.uncovered_classes

    # And the rendered report's completeness gate is FAIL.
    renderer = ReportRenderer(Jinja2TemplateRenderer(), RedactionEngine())
    rendered = renderer.render(
        ReportData(
            assessment_id="assess-1",
            title="incomplete",
            scope_summary="scope",
            method="method",
            findings=(),
            coverage_rate=report.coverage_rate,
            uncovered_classes=report.uncovered_classes,
        ),
        report_id="report-2",
    )
    assert rendered.completeness_ok is False
