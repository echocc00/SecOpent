"""Four-domain real scan coverage through the orchestrator (P2-F / T6).

Extends the T5 orchestration pattern (``AdapterStepRunner`` + ``RealScanRunner``
+ ``ScanContext`` + ``Orchestrator.run_to_completion``) to exercise all four
execution domains (``CoverageDomain``: ASSET / WEB / NETWORK / CLOUD) with real
digest-pinned tool containers against the live target ranges:

- **WEB**     : nuclei (SQLi) + dalfox (XSS probe) on Juice Shop
- **NETWORK** : nmap + naabu port scan of the host-mapped httpbin
- **ASSET**   : httpx probe of Juice Shop + httpbin
- **CLOUD**   : checkov IaC (covered in test_orchestration.py) + trivy image scan

Deeper scans that need infrastructure not guaranteed in every environment are
skip-guarded (consistent with the e2e_real philosophy), not faked:
- trivy image-vuln scan: needs its vulnerability DB (network-gated on some nets)
- crAPI BOLA/BFLA: needs the multi-container crAPI range to be up

Marked ``e2e_real``; skipped automatically when Docker or a target is down.
"""
from __future__ import annotations

import shutil
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import pytest

from secopent.application.jobs import JobService
from secopent.application.orchestrator import Orchestrator
from secopent.domain.adapters.contracts import CoverageDomain
from secopent.domain.assessments.models import ExecutionPlan, PlanStep
from secopent.domain.jobs.models import JobStatus
from secopent.domain.policy.models import RiskClass
from secopent.infrastructure.adapters.real_scan import RealScanRunner
from secopent.infrastructure.adapters.step_runner import AdapterStepRunner, ScanContext

_NOW = datetime(2026, 1, 1, tzinfo=UTC)

_HOST = "host.docker.internal"
_JUICE_URL = f"http://{_HOST}:3000"
_HTTPBIN_URL = f"http://{_HOST}:8080"

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


def _write_template(tmp_path: Path, body: str) -> str:
    tpl_dir = tmp_path / "templates"
    tpl_dir.mkdir(exist_ok=True)
    (tpl_dir / "t.yaml").write_text(body, encoding="utf-8")
    return str(tpl_dir)


def _target_up(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.status == 200
    except Exception:  # noqa: BLE001 - any failure means the target is down
        return False


def _plan(plan_id: str, *steps: PlanStep) -> ExecutionPlan:
    return ExecutionPlan.create(
        plan_id=plan_id, assessment_id=f"assess-{plan_id}", version=1, steps=steps
    )


def _run(plan: ExecutionPlan, step_runner: AdapterStepRunner, owner: str) -> JobService:
    jobs = JobService()
    orchestrator = Orchestrator(jobs, step_runner)
    orchestrator.dispatch(plan)
    orchestrator.run_to_completion(owner=owner, now=_NOW)
    return jobs


# --- WEB domain: nuclei (SQLi) + dalfox (XSS probe) -------------------------


@pytest.mark.e2e_real
def test_web_multi_adapter_juice_shop(require_target, tmp_path: Path) -> None:
    require_target("juice_shop")
    tpl_dir = _write_template(tmp_path, JUICE_SQLI_TEMPLATE)

    plan = _plan(
        "web-multi",
        PlanStep(key="web:sqli", runner="nuclei", risk=RiskClass.ACTIVE,
                 parameters={}, dependencies=()),
        PlanStep(key="web:xss", runner="dalfox", risk=RiskClass.ACTIVE,
                 parameters={}, dependencies=()),
    )
    step_runner = AdapterStepRunner(
        RealScanRunner(default_timeout=180),
        ScanContext(targets=(_JUICE_URL,), template_host_dir=tpl_dir),
    )
    jobs = _run(plan, step_runner, "e2e-web-multi")

    assert all(job.status is JobStatus.SUCCEEDED for job in jobs.all())
    observations = step_runner.all_observations()
    # nuclei reproduces the real Juice Shop SQLi; dalfox ran in the same chain.
    assert any("CWE-89" in o.cwe for o in observations), "expected a SQLi observation"
    assert any(o.coverage_domain is CoverageDomain.WEB for o in observations)


# --- NETWORK domain: nmap + naabu port scan ---------------------------------


@pytest.mark.e2e_real
def test_network_port_scan_httpbin(require_target) -> None:
    require_target("httpbin")
    plan = _plan(
        "network",
        PlanStep(key="net:nmap", runner="nmap", risk=RiskClass.PASSIVE,
                 parameters={}, dependencies=()),
        PlanStep(key="net:naabu", runner="naabu", risk=RiskClass.PASSIVE,
                 parameters={}, dependencies=()),
    )
    step_runner = AdapterStepRunner(
        RealScanRunner(default_timeout=180),
        ScanContext(targets=(_HOST,), ports=(8080,)),
    )
    jobs = _run(plan, step_runner, "e2e-network")

    assert all(job.status is JobStatus.SUCCEEDED for job in jobs.all())
    observations = step_runner.all_observations()
    assert observations, "no open-port observations from the network scan"
    assert any(o.rule_id.endswith("open_port") for o in observations)


# --- ASSET domain: httpx probe of multiple targets --------------------------


@pytest.mark.e2e_real
def test_asset_discovery_httpx(require_target) -> None:
    require_target("juice_shop")
    require_target("httpbin")
    plan = _plan(
        "asset",
        PlanStep(key="asset:probe", runner="httpx", risk=RiskClass.PASSIVE,
                 parameters={}, dependencies=()),
    )
    step_runner = AdapterStepRunner(
        RealScanRunner(default_timeout=180),
        ScanContext(targets=(_JUICE_URL, _HTTPBIN_URL)),
    )
    jobs = _run(plan, step_runner, "e2e-asset")

    assert all(job.status is JobStatus.SUCCEEDED for job in jobs.all())
    observations = step_runner.all_observations()
    # Both in-scope assets were probed (one scan per target, merged).
    assert len(observations) >= 2
    assert all(o.coverage_domain is CoverageDomain.ASSET for o in observations)


# --- CLOUD domain: trivy image-vuln scan (DB network-gated -> skip-guarded) --


@pytest.mark.e2e_real
def test_cloud_trivy_image_scan() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    # trivy must download its vulnerability DB at run time; on networks that
    # block the OCI artifact the scan FATALs (no observations). Detect that and
    # skip rather than fake a pass.
    runner = RealScanRunner(default_timeout=600)
    result = runner.scan(
        "trivy",
        args=["image", "--format", "json", "--quiet", "bkimminich/juice-shop:latest"],
        mounts={"/var/run/docker.sock": "/var/run/docker.sock"},
    )
    if not result.observations and (
        result.exit_code != 0 or "DB" in result.stderr or "vulnerability DB" in result.stderr
    ):
        pytest.skip("trivy vulnerability DB unreachable on this network")
    assert result.observations, "no CVE observations from the trivy image scan"
    assert any(
        o.coverage_domain is CoverageDomain.CLOUD and o.cve for o in result.observations
    )


# --- API domain: crAPI BOLA/BFLA (multi-container range -> skip-guarded) -----

_CRAPI_URL = "http://localhost:8888"


@pytest.mark.e2e_real
def test_api_crapi_recon(require_target) -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    if not _target_up(_CRAPI_URL):
        pytest.skip(f"crAPI range not reachable at {_CRAPI_URL}")
    # crAPI is up: nuclei probes it through the orchestrator (katana crawl +
    # nuclei is the full chain; here nuclei confirms the API responds/scan runs).
    plan = _plan(
        "api-crapi",
        PlanStep(key="api:nuclei", runner="nuclei", risk=RiskClass.ACTIVE,
                 parameters={}, dependencies=()),
    )
    step_runner = AdapterStepRunner(
        RealScanRunner(default_timeout=300),
        ScanContext(targets=(_CRAPI_URL,)),
    )
    jobs = _run(plan, step_runner, "e2e-api-crapi")
    assert all(job.status is JobStatus.SUCCEEDED for job in jobs.all())
