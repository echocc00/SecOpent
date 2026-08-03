"""Real end-to-end ORCHESTRATION tests (P3 §3.2 / T5).

Where ``test_real_scans.py`` drives a single adapter directly, these tests drive
the FULL assessment chain *through the Orchestrator*: the Planner emits a real
ExecutionPlan DAG, ``Orchestrator.dispatch`` creates leased jobs, and
``Orchestrator.run_to_completion`` executes each step via the new
:class:`AdapterStepRunner` glue (PlanStep -> RealScanRunner -> real digest-pinned
container -> Observations). The correlated findings then flow through the oracle
(N/N real reproduction), the coverage gate, and the data-driven report.

This is the §3.2 hard gate: it proves the three asset domains (Web / API / cloud)
orchestrate end-to-end with real tool containers and no mocks.

Marked ``e2e_real``; skipped automatically when Docker or a target range is down.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from secopent.application.canary import CanaryTokenManager
from secopent.application.coverage import CoverageService
from secopent.application.finding_correlation import FindingCorrelation
from secopent.application.jobs import JobService
from secopent.application.oracle import OracleEngine
from secopent.application.orchestrator import Orchestrator
from secopent.application.planner import Planner
from secopent.application.report_renderer import ReportData, ReportRenderer
from secopent.domain.adapters.contracts import CoverageDomain
from secopent.domain.catalog.models import AssetType, RequiredTestClass, TestCatalog
from secopent.domain.findings.models import FindingStatus
from secopent.domain.jobs.models import JobStatus
from secopent.domain.policy.models import RiskClass
from secopent.domain.verification.models import (
    CandidateFinding,
    VerificationStatus,
    VulnType,
)
from secopent.domain.verification.registry import default_registry
from secopent.infrastructure.adapters.real_scan import RealScanRunner
from secopent.infrastructure.adapters.step_runner import AdapterStepRunner, ScanContext
from secopent.infrastructure.evidence_store.redaction import RedactionEngine
from secopent.infrastructure.oracle.rescan_verifier import RescanVerifier
from secopent.infrastructure.report_templates.renderer import Jinja2TemplateRenderer

_NOW = datetime(2026, 1, 1, tzinfo=UTC)

# In-container reachability: the nuclei container reaches the host-mapped target
# ranges through host.docker.internal (the host-side health check uses localhost).
_JUICE_CONTAINER_URL = "http://host.docker.internal:3000"
_HTTPBIN_CONTAINER_URL = "http://host.docker.internal:8080"

# Proven live Juice Shop login SQLi bypass (verified in test_real_scans.py).
JUICE_SQLI_TEMPLATE = """\
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

# Proven live httpbin status probe (verified in test_real_scans.py).
HTTPBIN_STATUS_TEMPLATE = """\
id: httpbin-status-200
info:
  name: httpbin status endpoint
  author: secopent
  severity: info
  tags: tech,httpbin
http:
  - method: GET
    path:
      - "{{BaseURL}}/status/200"
    matchers:
      - type: status
        status:
          - 200
"""


class _NullAudit:
    """Minimal audit sink for the CanaryTokenManager in real E2E."""

    def record(self, **_: object) -> None:
        return None


def _write_template(base_dir: Path, body: str) -> str:
    tpl_dir = base_dir / "templates"
    tpl_dir.mkdir(exist_ok=True)
    (tpl_dir / "t.yaml").write_text(body, encoding="utf-8")
    return str(tpl_dir)


@pytest.mark.e2e_real
def test_web_orchestration_juice_shop_full_chain(require_target, docker_mount_dir: Path) -> None:
    """Web domain: Planner -> Orchestrator -> real nuclei -> oracle -> gate -> report."""
    require_target("juice_shop")
    tpl_dir = _write_template(docker_mount_dir, JUICE_SQLI_TEMPLATE)

    # 1. Planner emits a real DAG from the pinned catalog (single required class
    #    so the coverage gate legitimately closes at 100%).
    catalog = TestCatalog(
        version="2026.07",
        mappings={
            AssetType.WEB_APP: (
                RequiredTestClass(
                    id="sqli", cwe=("CWE-89",), owasp=("A03:2021",), risk=RiskClass.ACTIVE
                ),
            )
        },
    )
    plan = Planner(catalog).generate(
        plan_id="plan-web", assessment_id="assess-web", asset_types=[AssetType.WEB_APP]
    )
    assert len(plan.steps) == 1
    assert plan.steps[0].runner == "nuclei"  # WEB_APP default adapter

    # 2. Dispatch leased jobs + run to completion through the AdapterStepRunner.
    jobs = JobService()
    scan_runner = RealScanRunner(default_timeout=180)
    step_runner = AdapterStepRunner(
        scan_runner,
        ScanContext(targets=(_JUICE_CONTAINER_URL,), template_host_dir=tpl_dir),
    )
    orchestrator = Orchestrator(jobs, step_runner)
    orchestrator.dispatch(plan)
    orchestrator.run_to_completion(owner="e2e-web", now=_NOW)

    # 3. Every dispatched job succeeded via a real container scan.
    assert jobs.all(), "orchestrator created no jobs"
    assert all(job.status is JobStatus.SUCCEEDED for job in jobs.all())
    observations = step_runner.all_observations()
    assert observations, "no observations from orchestrated real nuclei scan"
    assert any("CWE-89" in o.cwe for o in observations), "expected a SQLi observation"

    # 4. Correlate -> findings.
    findings = FindingCorrelation().correlate(observations)
    assert findings
    finding = next(f for f in findings if "CWE-89" in f.cwe)

    # 5. Oracle confirms at N/N by REAL reproduction (re-scan).
    candidate = CandidateFinding(
        id=finding.id,
        observation_id=finding.observation_ids[0],
        vuln_type=VulnType.SQLI,
        target=finding.asset,
    )
    engine = OracleEngine(
        registry=default_registry(),
        verifier=RescanVerifier(
            scan_runner,
            {
                "adapter_key": "nuclei",
                "args": [
                    "-t",
                    "/templates/",
                    "-u",
                    _JUICE_CONTAINER_URL,
                    "-jsonl",
                    "-silent",
                    "-duc",
                ],
                "mounts": {"/templates": tpl_dir},
            },
        ),
        canary=CanaryTokenManager(_NullAudit()),
    )
    verification = engine.verify(candidate, actor="oracle")
    assert verification.status is VerificationStatus.CONFIRMED, verification.reason
    confirmed = engine.confirm(
        candidate, verification, evidence_ids=("ev-web-orch",), verified_at=_NOW
    )
    assert confirmed.successes == verification.attempts  # N/N

    # 6. Coverage gate closes (the required SQLi class is covered).
    coverage = CoverageService().compute(AssetType.WEB_APP, observations, catalog)
    CoverageService().enforce_gate(coverage)  # no raise
    assert coverage.coverage_rate == 1.0

    # 7. Data-driven report renders complete with the confirmed evidence.
    validated = replace(
        finding,
        evidence_ids=confirmed.evidence_ids,
        status=FindingStatus.VALIDATED,
    )
    report = ReportRenderer(Jinja2TemplateRenderer(), RedactionEngine()).render(
        ReportData(
            assessment_id="assess-web",
            title="Juice Shop orchestrated assessment",
            scope_summary=f"Authorized orchestrated test of {_JUICE_CONTAINER_URL}",
            method="Planner -> Orchestrator -> real nuclei scan -> oracle N/N.",
            findings=(validated,),
            coverage_rate=coverage.coverage_rate,
            uncovered_classes=coverage.uncovered_classes,
            evidence_digests=("sha256:" + "e" * 64,),
            assets=(_JUICE_CONTAINER_URL,),
        ),
        report_id="report-web-orch",
    )
    assert report.completeness_ok is True
    assert report.finding_count == 1


@pytest.mark.e2e_real
def test_api_orchestration_httpbin_full_chain(require_target, docker_mount_dir: Path) -> None:
    """API domain: the same orchestration chain against an API target (httpbin)."""
    require_target("httpbin")
    tpl_dir = _write_template(docker_mount_dir, HTTPBIN_STATUS_TEMPLATE)

    catalog = TestCatalog(
        version="2026.07",
        mappings={
            AssetType.API: (
                RequiredTestClass(
                    id="api-probe",
                    cwe=(),
                    owasp=(),
                    risk=RiskClass.PASSIVE,
                ),
            )
        },
    )
    plan = Planner(catalog).generate(
        plan_id="plan-api", assessment_id="assess-api", asset_types=[AssetType.API]
    )
    assert plan.steps and plan.steps[0].runner == "nuclei"  # API default adapter

    jobs = JobService()
    step_runner = AdapterStepRunner(
        RealScanRunner(default_timeout=180),
        ScanContext(targets=(_HTTPBIN_CONTAINER_URL,), template_host_dir=tpl_dir),
    )
    orchestrator = Orchestrator(jobs, step_runner)
    orchestrator.dispatch(plan)
    orchestrator.run_to_completion(owner="e2e-api", now=_NOW)

    assert all(job.status is JobStatus.SUCCEEDED for job in jobs.all())
    observations = step_runner.all_observations()
    assert observations, "no observations from orchestrated API scan"
    # The scan reached the API target from inside the container.
    assert any(
        "host.docker.internal:8080" in o.asset_identity for o in observations
    )
    # Observations correlate into reportable findings.
    assert FindingCorrelation().correlate(observations)


# --- Scenario 3: cloud/container (checkov IaC misconfig scan) ---------------
#
# The plan's cloud scenario is a container-image vuln scan (trivy). trivy is
# wired into the RealScanRunner and its AdapterStepRunner invocation, but it
# requires downloading its vulnerability DB at run time, which the China network
# interrupts (mirror.gcr.io/aquasec/trivy-db -> unexpected EOF). To keep the
# cloud-domain proof deterministic and offline, this scenario uses checkov - the
# same cloud/container domain, scanning IaC manifests with bundled rules (no
# external DB). It exercises the identical Planner -> Orchestrator -> Adapter
# chain and produces real CLOUD-domain findings.

_CHECKOV_IMAGE = "bridgecrew/checkov:latest"

# Deliberately-misconfigured IaC that checkov reliably flags.
_INSECURE_POD_YAML = """\
apiVersion: v1
kind: Pod
metadata:
  name: insecure
spec:
  containers:
    - name: app
      image: alpine:3.18
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
"""
_INSECURE_DOCKERFILE = "FROM alpine:3.18\nRUN apk add --no-cache curl\n"


def _docker_image_present(ref: str) -> bool:
    """True if an image ref is available locally (no pull attempted)."""
    try:
        proc = subprocess.run(  # noqa: S603 - fixed docker args, not a shell
            ["docker", "image", "inspect", ref],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def _write_iac(tmp_path: Path) -> str:
    iac_dir = tmp_path / "iac"
    iac_dir.mkdir(exist_ok=True)
    (iac_dir / "Dockerfile").write_text(_INSECURE_DOCKERFILE, encoding="utf-8")
    (iac_dir / "pod.yaml").write_text(_INSECURE_POD_YAML, encoding="utf-8")
    return str(iac_dir)


@pytest.mark.e2e_real
def test_cloud_orchestration_checkov_iac_scan(tmp_path: Path) -> None:
    """Cloud/container domain: checkov IaC scan through the orchestrator.

    The Planner selects the checkov adapter for the container asset; the
    orchestrator runs it via AdapterStepRunner against a mounted directory of
    deliberately-insecure IaC, producing real CLOUD-domain misconfig findings.
    Skipped when docker or the checkov image is unavailable.
    """
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    if not _docker_image_present(_CHECKOV_IMAGE):
        pytest.skip("checkov image not available locally")
    iac_dir = _write_iac(tmp_path)

    catalog = TestCatalog(
        version="2026.07",
        mappings={
            AssetType.CONTAINER_K8S: (
                RequiredTestClass(
                    id="iac-misconfig", cwe=(), owasp=(), risk=RiskClass.PASSIVE
                ),
            )
        },
    )
    # runner_map overrides the CONTAINER_K8S default (trivy) with checkov.
    plan = Planner(catalog, runner_map={AssetType.CONTAINER_K8S: "checkov"}).generate(
        plan_id="plan-cloud",
        assessment_id="assess-cloud",
        asset_types=[AssetType.CONTAINER_K8S],
    )
    assert plan.steps and plan.steps[0].runner == "checkov"

    jobs = JobService()
    step_runner = AdapterStepRunner(
        RealScanRunner(default_timeout=300),
        ScanContext(targets=("iac-scan",), template_host_dir=iac_dir),
    )
    orchestrator = Orchestrator(jobs, step_runner)
    orchestrator.dispatch(plan)
    orchestrator.run_to_completion(owner="e2e-cloud", now=_NOW)

    assert all(job.status is JobStatus.SUCCEEDED for job in jobs.all())
    observations = step_runner.all_observations()
    assert observations, "no misconfig observations from orchestrated checkov scan"
    # checkov findings are real cloud/container observations.
    assert all(o.coverage_domain is CoverageDomain.CLOUD for o in observations)
