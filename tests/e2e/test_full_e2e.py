"""Full end-to-end assessment with security layers (M5 Task 10, §13 / §16.2).

Runs the complete chain for three range archetypes - Juice Shop (web/SQLi),
crAPI (API/IDOR), httpbin (web/XSS) - with the M5 security layers in the path:
scope enforcement (in-scope allowed, out-of-scope denied), a signed short-lived
execution permit, a signed audit chain, oracle N/N confirmation, the coverage
gate, and a data-driven complete report.

Real docker-compose ranges (Juice Shop/crAPI/vulhub/httpbin) run in a
Docker-enabled environment; the adapter backend is mocked here. The orchestration
+ security decisions exercised are the real components.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

import pytest

from secopent.application.audit_chain import AuditChain
from secopent.application.canary import CanaryTokenManager
from secopent.application.coverage import CoverageService
from secopent.application.finding_correlation import FindingCorrelation
from secopent.application.jobs import JobService
from secopent.application.oracle import OracleEngine
from secopent.application.orchestrator import Orchestrator, StepResult
from secopent.application.planner import Planner
from secopent.application.report_renderer import ReportData, ReportRenderer
from secopent.application.scope_enforcer import EnforcementContext, ScopeEnforcer
from secopent.domain.adapters.contracts import (
    AdapterSource,
    CoverageDomain,
    Observation,
    Severity,
)
from secopent.domain.catalog.models import AssetType, RequiredTestClass, TestCatalog
from secopent.domain.findings.models import FindingStatus
from secopent.domain.jobs.models import JobStatus
from secopent.domain.permits.models import DEFAULT_PERMIT_TTL_SECONDS, ExecutionPermit
from secopent.domain.policy.models import RiskClass
from secopent.domain.scope.models import ScopeDraft
from secopent.domain.verification.models import (
    CandidateFinding,
    ReproductionStatus,
    VerificationStatus,
    VulnType,
)
from secopent.domain.verification.registry import default_registry
from secopent.infrastructure.audit.key_manager import AuditKeyManager
from secopent.infrastructure.evidence_store.redaction import RedactionEngine
from secopent.infrastructure.permits.permit_signer import PermitSigner, PermitVerifier
from secopent.infrastructure.report_templates.renderer import Jinja2TemplateRenderer

_T0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
_SOURCE = AdapterSource(name="scanner", version="1.0.0", template_version="1.0.0")


@dataclass(frozen=True)
class _Range:
    name: str
    asset_type: AssetType
    test_class: str
    cwe: str
    vuln: VulnType
    target: str


_RANGES = [
    _Range("juice_shop", AssetType.WEB_APP, "sqli", "CWE-89", VulnType.SQLI, "https://juice-shop.test/"),
    _Range("crapi", AssetType.API, "idor", "CWE-639", VulnType.IDOR, "https://crapi.test/"),
    _Range("httpbin", AssetType.WEB_APP, "xss", "CWE-79", VulnType.XSS, "https://httpbin.test/"),
]


class _EmittingRunner:
    def __init__(self, observations: list[Observation], cwe: str) -> None:
        self._observations = observations
        self._cwe = cwe
        self._n = 0

    def run(self, step) -> StepResult:  # type: ignore[no-untyped-def]
        self._n += 1
        self._observations.append(
            Observation(
                external_id=f"obs-{self._n}",
                asset_identity="https://target.test/",
                source=_SOURCE,
                rule_id=step.key,
                rule_version="1.0.0",
                coverage_domain=CoverageDomain.WEB,
                title=f"{step.parameters.get('test_class')} finding",
                severity=Severity.HIGH,
                confidence=0.9,
                cwe=(self._cwe,),
            )
        )
        return StepResult(result_digest="sha256:" + "d" * 64)


class _AlwaysSucceed:
    def reproduce(self, candidate, method, *, canary_token) -> ReproductionStatus:  # type: ignore[no-untyped-def]
        return ReproductionStatus.SUCCESS


class _AlwaysSucceedResolver:
    def resolve(self, host: str) -> tuple[str, ...]:
        return ("192.0.2.10",)


def _catalog(rng: _Range) -> TestCatalog:
    return TestCatalog(
        version="2026.07",
        mappings={
            rng.asset_type: (
                RequiredTestClass(
                    id=rng.test_class,
                    cwe=(rng.cwe,),
                    owasp=("A03:2021",),
                    risk=RiskClass.ACTIVE,
                ),
            )
        },
    )


@pytest.mark.parametrize("rng", _RANGES, ids=[r.name for r in _RANGES])
def test_full_e2e_with_security_layers(rng: _Range) -> None:
    # --- Scope: in-scope allowed, out-of-scope denied (conditions 1/2) ---
    snapshot = ScopeDraft(
        project_id="proj-1",
        include=("juice-shop.test", "crapi.test", "httpbin.test", "192.0.2.0/24"),
    ).freeze(snapshot_id="scope-1", approved_by="analyst")
    enforcer = ScopeEnforcer(_AlwaysSucceedResolver())
    ctx = EnforcementContext(
        risk=RiskClass.ACTIVE,
        approved_risks=frozenset({RiskClass.PASSIVE, RiskClass.LOW, RiskClass.ACTIVE}),
        approved=True,
        budget_remaining=100.0,
        now=_T0,
        permit_valid=True,
    )
    assert enforcer.check(rng.target, snapshot, ctx).allowed is True
    assert enforcer.check("https://evil.test/", snapshot, ctx).allowed is False

    # --- Signed short-lived execution permit (condition 5) ---
    signer = PermitSigner()
    permit = signer.issue(
        ExecutionPermit(
            job_id=f"job-{rng.name}",
            worker_id="worker-1",
            scope_digest=snapshot.digest,
            plan_digest="sha256:" + "p" * 64,
            capabilities=("passive",),
            budget=100.0,
            issued_at=_T0,
            expires_at=_T0 + timedelta(seconds=DEFAULT_PERMIT_TTL_SECONDS),
            nonce=f"nonce-{rng.name}",
        )
    )
    PermitVerifier(signer.public_key_bytes()).verify(
        permit, now=_T0, used_nonces=set(), expected_worker="worker-1"
    )

    # --- Planner -> Orchestrator -> observations ---
    catalog = _catalog(rng)
    plan = Planner(catalog).generate(
        plan_id=f"plan-{rng.name}", assessment_id=f"assess-{rng.name}", asset_types=[rng.asset_type]
    )
    observations: list[Observation] = []
    orchestrator = Orchestrator(JobService(), _EmittingRunner(observations, rng.cwe))
    orchestrator.dispatch(plan)
    orchestrator.run_to_completion(owner="worker-1", now=_T0)
    assert all(j.status is JobStatus.SUCCEEDED for j in orchestrator._jobs.all())
    assert len(observations) == 1

    # --- Signed audit chain records the run (condition 12) ---
    chain = AuditChain(AuditKeyManager())
    chain.record_permit_nonce(actor="worker-1", job_id=f"job-{rng.name}", permit_nonce=permit.nonce)
    chain.record(
        actor="orchestrator",
        action="assessment.run",
        resource_type="assessment",
        resource_id=f"assess-{rng.name}",
        payload={"observations": len(observations)},
    )
    assert chain.verify() is True
    assert permit.nonce in chain.permit_nonces()

    # --- Correlate -> oracle N/N -> VALIDATED ---
    findings = FindingCorrelation().correlate(observations)
    assert len(findings) == 1
    engine = OracleEngine(
        registry=default_registry(),
        verifier=_AlwaysSucceed(),
        canary=CanaryTokenManager(_AuditService()),
    )
    candidate = CandidateFinding(
        id=findings[0].id,
        observation_id=findings[0].observation_ids[0],
        vuln_type=rng.vuln,
        target=findings[0].asset,
    )
    result = engine.verify(candidate, actor="oracle")
    assert result.status is VerificationStatus.CONFIRMED
    validated = replace(findings[0], status=FindingStatus.VALIDATED)

    # --- Coverage gate passes ---
    report = CoverageService().compute(rng.asset_type, observations, catalog)
    CoverageService().enforce_gate(report)  # no raise
    assert report.coverage_rate == 1.0

    # --- Data-driven report renders complete ---
    rendered = ReportRenderer(Jinja2TemplateRenderer(), RedactionEngine()).render(
        ReportData(
            assessment_id=f"assess-{rng.name}",
            title=f"{rng.name} assessment",
            scope_summary=f"Authorized test of {rng.target}",
            method="Catalog-driven active assessment with oracle N/N.",
            findings=(validated,),
            coverage_rate=report.coverage_rate,
            uncovered_classes=report.uncovered_classes,
            evidence_digests=("sha256:" + "e" * 64,),
            assets=(rng.target,),
        ),
        report_id=f"report-{rng.name}",
    )
    assert rendered.completeness_ok is True
    assert rendered.finding_count == 1


class _AuditService:
    """Minimal AuditService stand-in for the CanaryTokenManager in E2E."""

    def record(self, **kwargs: object) -> None:
        return None
