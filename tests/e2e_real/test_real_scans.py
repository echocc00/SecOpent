"""Real end-to-end tests against live target ranges (Phase A Task A3).

These run the REAL chain with no mocks: real nuclei container (digest-pinned)
scans a live target -> real JSONL parsed into Observations -> correlated into
Findings -> the oracle confirms at N/N by REAL reproduction (re-scan) -> the
coverage gate and data-driven report run.

ptai-based verification is Phase A4; here the oracle's verifier reproduces by
re-running the real scan (deterministic reproduction), which is a legitimate
oracle for reproducible findings.

Marked ``e2e_real``; skipped automatically when Docker or a target is down.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from secopent.application.canary import CanaryTokenManager
from secopent.application.coverage import CoverageService
from secopent.application.finding_correlation import FindingCorrelation
from secopent.application.oracle import OracleEngine
from secopent.application.report_renderer import ReportData, ReportRenderer
from secopent.domain.catalog.models import AssetType, RequiredTestClass, TestCatalog
from secopent.domain.findings.models import FindingStatus
from secopent.domain.policy.models import RiskClass
from secopent.domain.verification.models import (
    CandidateFinding,
    VerificationStatus,
    VulnType,
)
from secopent.domain.verification.registry import default_registry
from secopent.infrastructure.adapters.real_scan import RealScanRunner
from secopent.infrastructure.evidence_store.redaction import RedactionEngine
from secopent.infrastructure.oracle.rescan_verifier import RescanVerifier
from secopent.infrastructure.report_templates.renderer import Jinja2TemplateRenderer

_NOW = datetime(2026, 1, 1, tzinfo=UTC)

# Real Juice Shop login SQLi bypass (verified to hit a live Juice Shop).
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

# Real httpbin status check.
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

_CWE_TO_VULN = {"CWE-89": VulnType.SQLI, "CWE-79": VulnType.XSS}


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
def test_juice_shop_real_sqli_full_chain(require_target, docker_mount_dir: Path) -> None:
    require_target("juice_shop")
    tpl_dir = _write_template(docker_mount_dir, JUICE_SQLI_TEMPLATE)
    runner = RealScanRunner(default_timeout=180)
    scan_kwargs = {
        "adapter_key": "nuclei",
        "args": [
            "-t",
            "/templates/",
            "-u",
            "http://host.docker.internal:3000",
            "-jsonl",
            "-silent",
            "-duc",
        ],
        "mounts": {"/templates": tpl_dir},
    }

    # 1. Real scan -> real observations.
    result = runner.scan(**scan_kwargs)
    assert result.exit_code == 0, f"nuclei failed: {result.stderr[-300:]}"
    assert result.observations, "no observations parsed from real nuclei output"
    sqli_obs = [o for o in result.observations if "CWE-89" in o.cwe]
    assert sqli_obs, "expected a CWE-89 (SQLi) observation from real scan"

    # 2. Correlate -> findings.
    findings = FindingCorrelation().correlate(result.observations)
    assert findings, "no findings correlated"
    finding = next(f for f in findings if "CWE-89" in f.cwe)

    # 3. Oracle confirms at N/N by real reproduction.
    candidate = CandidateFinding(
        id=finding.id,
        observation_id=finding.observation_ids[0],
        vuln_type=_CWE_TO_VULN["CWE-89"],
        target=finding.asset,
    )
    engine = OracleEngine(
        registry=default_registry(),
        verifier=RescanVerifier(runner, scan_kwargs),
        canary=CanaryTokenManager(_NullAudit()),
    )
    verification = engine.verify(candidate, actor="oracle")
    assert verification.status is VerificationStatus.CONFIRMED, verification.reason
    confirmed = engine.confirm(
        candidate, verification, evidence_ids=("ev-real-1",), verified_at=_NOW
    )
    assert confirmed.successes == verification.attempts  # N/N

    # 4. Coverage gate passes (sqli required class covered by the CWE-89 obs).
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
    coverage = CoverageService().compute(AssetType.WEB_APP, result.observations, catalog)
    CoverageService().enforce_gate(coverage)  # no raise
    assert coverage.coverage_rate == 1.0

    # 5. Data-driven report renders complete.
    validated = replace(
        finding,
        evidence_ids=confirmed.evidence_ids,
        status=FindingStatus.VALIDATED,
    )
    report = ReportRenderer(Jinja2TemplateRenderer(), RedactionEngine()).render(
        ReportData(
            assessment_id="assess-juice-real",
            title="Juice Shop real assessment",
            scope_summary="Authorized test of http://host.docker.internal:3000",
            method="Real nuclei scan + oracle N/N reproduction.",
            findings=(validated,),
            coverage_rate=coverage.coverage_rate,
            uncovered_classes=coverage.uncovered_classes,
            evidence_digests=("sha256:" + "e" * 64,),
            assets=("http://host.docker.internal:3000",),
        ),
        report_id="report-juice-real",
    )
    assert report.completeness_ok is True
    assert report.finding_count == 1


@pytest.mark.e2e_real
def test_httpbin_real_scan_produces_observations(require_target, docker_mount_dir: Path) -> None:
    require_target("httpbin")
    tpl_dir = _write_template(docker_mount_dir, HTTPBIN_STATUS_TEMPLATE)
    runner = RealScanRunner(default_timeout=180)
    result = runner.scan(
        adapter_key="nuclei",
        args=[
            "-t",
            "/templates/",
            "-u",
            "http://host.docker.internal:8080",
            "-jsonl",
            "-silent",
            "-duc",
        ],
        mounts={"/templates": tpl_dir},
    )
    assert result.exit_code == 0, f"nuclei failed: {result.stderr[-300:]}"
    assert result.observations, "no observations from real httpbin scan"
    # asset_identity is the matched-at URL (host.docker.internal:8080 from inside
    # the container reaching the host-mapped httpbin target).
    assert any("host.docker.internal:8080" in o.asset_identity for o in result.observations)
