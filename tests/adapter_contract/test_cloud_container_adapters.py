"""TDD contract tests for the Cloud Container Adapter Pack (M1 Task 12, §8.2).

These tests exercise the parser layer of the five cloud-container adapters:
prowler (AWS/Azure/GCP config audit, CIS check items, JSON output), trivy
(container image + IaC + filesystem scan, JSON), kube_bench (Kubernetes CIS
benchmark, JSON), checkov (IaC scan, JSON), and scoutsuite (multi-cloud
audit, JSON). They use FIXTURE files - sample JSON captured from real tool
runs - rather than executing the real tools. Real container execution is M5
E2E scope. Real Prowler/Trivy/kube-bench/checkov/ScoutSuite are NOT installed
in the M1 environment.

Each adapter has five fixture classes:

- **positive**: well-formed tool output -> at least one Observation with
  `coverage_domain=cloud`, populated `asset_identity`, and (where applicable)
  populated `cwe`/`cve`/`owasp` tuples that feed CoverageMatrix.
- **negative**: empty-but-well-formed tool output -> zero Observations.
- **timeout**: a fixture simulating the tool timing out (exit_code != 0) ->
  AdapterRunner reports non-COMPLETED status.
- **scope_deny**: an out-of-scope target is blocked by the M0 PolicyEngine
  BEFORE the container runs.
- **malformed**: corrupt JSON output -> the parser returns zero Observations
  without raising.

Manifest tests assert each adapter's `manifest()` builds an
`AdapterManifest` whose `coverage_domain` includes `cloud`, with upstream
pin and risk class populated. The scoutsuite manifest additionally marks
itself `license=GPL-2` and `independent_process=True` (carried in
`permissions`) because ScoutSuite is GPL-2-licensed and per §8.2 must be
invoked as an independent subprocess rather than embedded as a library.
Prowler/Trivy/kube-bench/checkov are Apache/MIT and need no such marker.
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from secopent.domain.adapters.contracts import (
    AdapterInput,
    AdapterManifest,
    AdapterSource,
    CoverageDomain,
    ExecutionPolicy,
    OutputStatus,
)
from secopent.domain.policy.engine import evaluate as policy_evaluate
from secopent.domain.policy.models import RiskClass
from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot
from secopent.infrastructure.adapters.base import (
    AdapterRunner,
    ContainerResult,
    ScopeDeniedError,
)
from secopent.integrations.adapters import (
    checkov,
    kube_bench,
    prowler,
    scoutsuite,
    trivy,
)

# ---------------------------------------------------------------------------
# Test doubles (reused from test_network_host_adapters.py shape)
# ---------------------------------------------------------------------------


@dataclass
class FakeCASStore:
    base_dir: Path
    calls: list[tuple[str, bytes]] | None = None

    def __post_init__(self) -> None:
        if self.calls is None:
            self.calls = []

    def store(self, content: bytes, *, kind: str) -> str:
        import hashlib

        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        self.calls.append((digest, content))
        return f"cas://{kind}/{digest}"


class RecordingExecutor:
    """Mock ContainerExecutor; returns canned stdout/stderr/exit_code."""

    def __init__(
        self,
        *,
        stdout: str = "",
        stderr: str = "",
        exit_code: int = 0,
        artifacts: dict[str, bytes] | None = None,
        raise_on_call: Exception | None = None,
    ) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self._exit_code = exit_code
        self._artifacts = artifacts or {}
        self._raise_on_call = raise_on_call
        self.calls: list[dict[str, Any]] = []

    def run(
        self,
        *,
        image_digest: str,
        command: Sequence[str],
        mounts: dict[str, str],
        network_policy: str,
        resource_limits: dict[str, Any],
    ) -> ContainerResult:
        if self._raise_on_call is not None:
            raise self._raise_on_call
        self.calls.append(
            {
                "image_digest": image_digest,
                "command": list(command),
                "mounts": dict(mounts),
                "network_policy": network_policy,
                "resource_limits": dict(resource_limits),
            }
        )
        artifacts_dir = Path(self.calls[-1]["mounts"].get("/out", "/tmp/fake-out"))
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        for name, content in self._artifacts.items():
            (artifacts_dir / name).write_bytes(content)
        return ContainerResult(
            stdout=self._stdout,
            stderr=self._stderr,
            exit_code=self._exit_code,
            artifacts_dir=artifacts_dir,
        )


# ---------------------------------------------------------------------------
# Shared scope fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scope_snapshot() -> ScopeSnapshot:
    return ScopeSnapshot(
        id="snap-cloud",
        project_id="proj-1",
        include=("example.com", "10.0.0.0/24"),
        exclude=(),
        ports=(443,),
        limits=ScopeLimits(requests_per_second=5.0, concurrency=3, max_requests=50_000),
        approved_by="analyst",
        approved_at=datetime(2026, 1, 1, tzinfo=UTC),
        digest="sha256:" + "0" * 64,
        cloud_accounts=("aws:123456789012",),
    )


def _scope_dict(scope: ScopeSnapshot) -> dict[str, object]:
    return {
        "id": scope.id,
        "project_id": scope.project_id,
        "include": scope.include,
        "exclude": scope.exclude,
        "ports": scope.ports,
        "limits": {
            "requests_per_second": scope.limits.requests_per_second,
            "concurrency": scope.limits.concurrency,
            "max_requests": scope.limits.max_requests,
        },
        "approved_by": scope.approved_by,
        "approved_at": scope.approved_at.isoformat(),
        "digest": scope.digest,
        "cloud_accounts": scope.cloud_accounts,
    }


def _adapter_input(
    scope: ScopeSnapshot, targets: tuple[str, ...], options: dict[str, object] | None = None
) -> AdapterInput:
    return AdapterInput(
        run_id="run-cloud-1",
        engagement_id="eng-1",
        scope_snapshot=_scope_dict(scope),
        targets=targets,
        options=options or {},
        execution_policy=ExecutionPolicy(
            timeout_seconds=60, max_concurrency=2, network_profile="scoped-egress"
        ),
    )


# ---------------------------------------------------------------------------
# Adapter-under-test registry
# ---------------------------------------------------------------------------

_ADAPTER_MODULES = {
    "prowler": prowler,
    "trivy": trivy,
    "kube_bench": kube_bench,
    "checkov": checkov,
    "scoutsuite": scoutsuite,
}

_ADAPTER_SOURCE = AdapterSource(name="test", version="1.0.0", template_version="1.0.0")


def _build_runner(adapter_module: Any, tmp_path: Path) -> AdapterRunner:
    parser_entry = adapter_module.manifest().parser
    return AdapterRunner(
        executor=RecordingExecutor(),
        policy_engine=policy_evaluate,
        cas_store=FakeCASStore(base_dir=tmp_path),
        parser_registry={parser_entry: adapter_module.parse},
    )


def _fixture_path(adapter_name: str, fixture_file: str) -> Path:
    module = _ADAPTER_MODULES[adapter_name]
    base = Path(module.__file__).parent / "fixtures"
    return base / fixture_file


# ---------------------------------------------------------------------------
# Manifest tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("adapter_name", list(_ADAPTER_MODULES))
def test_manifest_loads_with_cloud_coverage(adapter_name: str) -> None:
    module = _ADAPTER_MODULES[adapter_name]
    manifest = module.manifest()
    assert isinstance(manifest, AdapterManifest)
    assert CoverageDomain.CLOUD in manifest.coverage_domain
    assert manifest.id
    assert manifest.version
    assert manifest.upstream.name
    assert manifest.upstream.version
    assert manifest.upstream.digest
    assert manifest.risk_class in RiskClass
    assert manifest.license
    assert manifest.parser
    assert manifest.digest  # computed


def test_prowler_manifest_specifics() -> None:
    m = prowler.manifest()
    assert m.id == "prowler"
    assert m.upstream.name == "prowler"
    assert m.risk_class in (RiskClass.PASSIVE, RiskClass.LOW)
    # Prowler is Apache-2.0 (no GPL marker needed).
    assert "independent_process" not in m.permissions, (
        "prowler is Apache-2.0 and must NOT carry the independent_process marker"
    )


def test_trivy_manifest_specifics() -> None:
    m = trivy.manifest()
    assert m.id == "trivy"
    assert m.upstream.name == "trivy"
    assert m.risk_class in (RiskClass.PASSIVE, RiskClass.LOW)
    assert "independent_process" not in m.permissions


def test_kube_bench_manifest_specifics() -> None:
    m = kube_bench.manifest()
    assert m.id == "kube_bench"
    assert m.upstream.name == "kube-bench"
    assert m.risk_class in (RiskClass.PASSIVE, RiskClass.LOW)
    assert "independent_process" not in m.permissions


def test_checkov_manifest_specifics() -> None:
    m = checkov.manifest()
    assert m.id == "checkov"
    assert m.upstream.name == "checkov"
    assert m.risk_class in (RiskClass.PASSIVE, RiskClass.LOW)
    assert "independent_process" not in m.permissions


def test_scoutsuite_manifest_marks_gpl_and_independent_process() -> None:
    """ScoutSuite is GPL-2-licensed (§8.2 table) and MUST be invoked as an
    independent subprocess, not embedded as a library. The manifest carries
    both facts: a GPL-2 license string and an `independent_process` marker in
    `permissions`.
    """
    m = scoutsuite.manifest()
    assert m.id == "scoutsuite"
    assert m.upstream.name == "ScoutSuite"
    # License must declare GPL-2 family.
    license_upper = m.license.upper()
    assert "GPL" in license_upper and ("2" in license_upper or "V2" in license_upper), (
        "scoutsuite manifest must declare a GPL-2 license (§8.2: GPL tools are "
        "called as independent subprocesses, never embedded as libraries)"
    )
    assert "independent_process" in m.permissions, (
        "scoutsuite manifest must mark independent_process via permissions"
    )


# ---------------------------------------------------------------------------
# prowler parser tests (AWS JSON: CIS check items)
# ---------------------------------------------------------------------------


def test_prowler_positive_parse() -> None:
    """Prowler JSON: each finding has check_id / status / Severity / Region /
    Account / check_title. Parser must surface at least one Observation with
    `coverage_domain=cloud`, populated asset_identity (account or region),
    severity from finding, and a CWE/OWASP attribution so CoverageMatrix can
    credit the corresponding cloud CIS coverage item.
    """
    raw = _fixture_path("prowler", "positive.json").read_text(encoding="utf-8")
    observations = prowler.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) >= 1
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.CLOUD
    assert obs.asset_identity  # account/region populated
    # Severity must be derived from the finding's Severity field.
    assert obs.severity  # non-default INFO when finding has Severity
    # raw preserves check_id so audit/CoverageMatrix can credit CIS items.
    assert "check_id" in obs.raw or "CheckId" in obs.raw


def test_prowler_negative_parse_returns_empty() -> None:
    raw = _fixture_path("prowler", "negative.json").read_text(encoding="utf-8")
    observations = prowler.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_prowler_malformed_parse_returns_empty() -> None:
    raw = _fixture_path("prowler", "malformed.json").read_text(encoding="utf-8")
    observations = prowler.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


# ---------------------------------------------------------------------------
# trivy parser tests (container image scan: VulnerabilityID / PkgName / Severity)
# ---------------------------------------------------------------------------


def test_trivy_positive_parse() -> None:
    """Trivy image-scan JSON: Results[].Vulnerabilities[] with VulnerabilityID
    (a CVE), PkgName, Severity. Parser must surface at least one Observation
    with `coverage_domain=cloud`, `cve` populated from VulnerabilityID, and
    severity from the finding's Severity field.
    """
    raw = _fixture_path("trivy", "positive.json").read_text(encoding="utf-8")
    observations = trivy.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) >= 1
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.CLOUD
    assert obs.asset_identity  # target image / path
    # Trivy findings carry a CVE (VulnerabilityID) - parser MUST extract it.
    has_cve = any(o.cve for o in observations)
    assert has_cve, (
        "trivy parser must extract CVE from VulnerabilityID so CoverageMatrix "
        "can credit the corresponding cloud coverage item"
    )
    # raw preserves PkgName so audit can reconstruct the scan.
    assert "PkgName" in obs.raw or "pkg_name" in obs.raw or "VulnerabilityID" in obs.raw


def test_trivy_negative_parse_returns_empty() -> None:
    raw = _fixture_path("trivy", "negative.json").read_text(encoding="utf-8")
    observations = trivy.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_trivy_malformed_parse_returns_empty() -> None:
    raw = _fixture_path("trivy", "malformed.json").read_text(encoding="utf-8")
    observations = trivy.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


# ---------------------------------------------------------------------------
# kube_bench parser tests (K8s CIS benchmark: controls[].results[])
# ---------------------------------------------------------------------------


def test_kube_bench_positive_parse() -> None:
    """kube-bench JSON: Controls[].Results[] with id / text / status. Parser
    must surface at least one Observation with `coverage_domain=cloud`,
    populated asset_identity (node/test id), and the CIS control id preserved
    in raw so CoverageMatrix can credit the corresponding CIS benchmark item.
    """
    raw = _fixture_path("kube_bench", "positive.json").read_text(encoding="utf-8")
    observations = kube_bench.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) >= 1
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.CLOUD
    assert obs.asset_identity  # node/control id
    # raw must preserve the CIS control id (id field) so CoverageMatrix can
    # credit the CIS benchmark coverage item.
    assert "id" in obs.raw or "test_id" in obs.raw or "control_id" in obs.raw


def test_kube_bench_negative_parse_returns_empty() -> None:
    raw = _fixture_path("kube_bench", "negative.json").read_text(encoding="utf-8")
    observations = kube_bench.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_kube_bench_malformed_parse_returns_empty() -> None:
    raw = _fixture_path("kube_bench", "malformed.json").read_text(encoding="utf-8")
    observations = kube_bench.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


# ---------------------------------------------------------------------------
# checkov parser tests (IaC scan: failed checks)
# ---------------------------------------------------------------------------


def test_checkov_positive_parse() -> None:
    """checkov JSON: results.failed_checks[] with check_id / check_name /
    file_path. Parser must surface at least one Observation with
    `coverage_domain=cloud`, asset_identity (file_path), and a CWE attribution
    from the curated check-id -> CWE map so CoverageMatrix can credit the
    IaC coverage item.
    """
    raw = _fixture_path("checkov", "positive.json").read_text(encoding="utf-8")
    observations = checkov.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) >= 1
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.CLOUD
    assert obs.asset_identity  # file_path
    # raw preserves check_id so audit/CoverageMatrix can credit CIS items.
    assert "check_id" in obs.raw or "CheckId" in obs.raw


def test_checkov_negative_parse_returns_empty() -> None:
    raw = _fixture_path("checkov", "negative.json").read_text(encoding="utf-8")
    observations = checkov.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_checkov_malformed_parse_returns_empty() -> None:
    raw = _fixture_path("checkov", "malformed.json").read_text(encoding="utf-8")
    observations = checkov.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_checkov_array_output_flattens_across_frameworks() -> None:
    """Real checkov (>=3.x) emits a JSON ARRAY of per-framework result objects
    when a directory holds several IaC kinds (e.g. a Dockerfile plus Kubernetes
    manifests). The parser must flatten ``failed_checks`` across EVERY block,
    not just treat the array as a single object (regression: array output used
    to yield zero observations). Surfaced by the T5 §3.2 cloud e2e scenario.
    """
    payload = [
        {
            "check_type": "kubernetes",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_K8S_16",
                        "check_name": "privileged container",
                        "file_path": "/pod.yaml",
                        "resource": "Pod.insecure",
                    }
                ]
            },
        },
        {
            "check_type": "dockerfile",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_DOCKER_3",
                        "check_name": "no USER created",
                        "file_path": "/Dockerfile",
                        "resource": "Dockerfile",
                    }
                ]
            },
        },
    ]
    observations = checkov.parse(
        stdout=json.dumps(payload), source=_ADAPTER_SOURCE, artifacts={}
    )
    assert len(observations) == 2  # one finding flattened from each framework block
    assert all(o.coverage_domain is CoverageDomain.CLOUD for o in observations)
    assert {o.rule_id for o in observations} == {"CKV_K8S_16", "CKV_DOCKER_3"}


# ---------------------------------------------------------------------------
# scoutsuite parser tests (multi-cloud audit: findings)
# ---------------------------------------------------------------------------


def test_scoutsuite_positive_parse() -> None:
    """ScoutSuite JSON: findings array keyed by service / finding_key. Parser
    must surface at least one Observation with `coverage_domain=cloud` and
    populated asset_identity (cloud account / region).
    """
    raw = _fixture_path("scoutsuite", "positive.json").read_text(encoding="utf-8")
    observations = scoutsuite.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) >= 1
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.CLOUD
    assert obs.asset_identity  # cloud account / region


def test_scoutsuite_negative_parse_returns_empty() -> None:
    raw = _fixture_path("scoutsuite", "negative.json").read_text(encoding="utf-8")
    observations = scoutsuite.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_scoutsuite_malformed_parse_returns_empty() -> None:
    raw = _fixture_path("scoutsuite", "malformed.json").read_text(encoding="utf-8")
    observations = scoutsuite.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


# ---------------------------------------------------------------------------
# Runner-level tests (timeout / scope_deny) - parametrized across 5 adapters
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("adapter_name", list(_ADAPTER_MODULES))
def test_timeout_fixture_produces_non_completed_output(
    adapter_name: str, scope_snapshot: ScopeSnapshot, tmp_path: Path
) -> None:
    module = _ADAPTER_MODULES[adapter_name]
    manifest = module.manifest()
    timeout_text = (Path(module.__file__).parent / "fixtures" / "timeout.txt").read_text(
        encoding="utf-8"
    )
    executor = RecordingExecutor(stdout="", stderr=timeout_text, exit_code=124)
    cas = FakeCASStore(base_dir=tmp_path)
    parser_entry = manifest.parser
    runner = AdapterRunner(
        executor=executor,
        policy_engine=policy_evaluate,
        cas_store=cas,
        parser_registry={parser_entry: module.parse},
    )
    # Cloud adapters operate on cloud accounts/images, not URLs/ports - use
    # an in-scope cloud-account target (matches the scope_snapshot include).
    targets = ("aws:123456789012",)
    adapter_input = _adapter_input(
        scope_snapshot, targets=targets, options={"ports": [443]}
    )
    output = runner.run(manifest, adapter_input)
    assert output.status is not OutputStatus.COMPLETED
    assert output.errors


@pytest.mark.parametrize("adapter_name", list(_ADAPTER_MODULES))
def test_scope_deny_blocks_before_container(
    adapter_name: str, scope_snapshot: ScopeSnapshot, tmp_path: Path
) -> None:
    module = _ADAPTER_MODULES[adapter_name]
    manifest = module.manifest()
    executor = RecordingExecutor(stdout="should-not-be-reached")
    cas = FakeCASStore(base_dir=tmp_path)
    parser_entry = manifest.parser
    runner = AdapterRunner(
        executor=executor,
        policy_engine=policy_evaluate,
        cas_store=cas,
        parser_registry={parser_entry: module.parse},
    )
    # Out-of-scope cloud-account target - not in scope_snapshot.include.
    out_of_scope_target = ("aws:999999999999",)
    adapter_input = _adapter_input(
        scope_snapshot, targets=out_of_scope_target, options={"ports": [443]}
    )
    with pytest.raises(ScopeDeniedError):
        runner.run(manifest, adapter_input)
    assert executor.calls == [], "container executed despite scope denial"
