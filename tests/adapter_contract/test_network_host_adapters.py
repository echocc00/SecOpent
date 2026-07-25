"""TDD contract tests for the Network Host Adapter Pack (M1 Task 11, §8.2).

These tests exercise the parser layer of the two network/host adapters:
nmap (service/OS scan + NSE vuln scripts, XML -oX output) and nuclei_tcp
(nuclei TCP/dns/ssl templates, JSONL output). They use FIXTURE files -
sample nmap XML and sample nuclei JSONL captured from real tool runs -
rather than executing the real tools. Real container execution is M5 E2E
scope. Real nmap is NOT installed in the M1 environment.

Each adapter has five fixture classes:

- **positive**: well-formed tool output -> at least one Observation with
  `coverage_domain=network`, `asset_identity` of the form `ip:port`
  (nmap) or host (nuclei_tcp), and (where applicable) populated
  `cwe`/`cve` tuples that feed CoverageMatrix.
- **negative**: empty-but-well-formed tool output -> zero Observations.
- **timeout**: a fixture simulating the tool timing out (exit_code != 0)
  -> AdapterRunner reports non-COMPLETED status.
- **scope_deny**: an out-of-scope target is blocked by the M0
  PolicyEngine BEFORE the container runs.
- **malformed**: corrupt XML/JSONL output -> the parser returns zero
  Observations without raising.

Manifest tests assert each adapter's `manifest()` builds an
`AdapterManifest` whose `coverage_domain` includes `network`, with
upstream pin and risk class populated. The nmap manifest additionally
marks itself `license=GPL` and `independent_process=True` (carried in
`permissions`) because nmap is GPL-licensed and per §8.2 must be invoked
as an independent subprocess rather than embedded as a library.
"""
from __future__ import annotations

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
from secopent.integrations.adapters import nmap, nuclei_tcp

# ---------------------------------------------------------------------------
# Test doubles (reused from test_web_api_adapters.py shape)
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
        id="snap-network",
        project_id="proj-1",
        include=("example.com", "10.0.0.0/24"),
        exclude=(),
        ports=(22, 80, 443),
        limits=ScopeLimits(requests_per_second=5.0, concurrency=3, max_requests=50_000),
        approved_by="analyst",
        approved_at=datetime(2026, 1, 1, tzinfo=UTC),
        digest="sha256:" + "0" * 64,
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
    }


def _adapter_input(
    scope: ScopeSnapshot, targets: tuple[str, ...], options: dict[str, object] | None = None
) -> AdapterInput:
    return AdapterInput(
        run_id="run-network-1",
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
    "nmap": nmap,
    "nuclei_tcp": nuclei_tcp,
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
def test_manifest_loads_with_network_coverage(adapter_name: str) -> None:
    module = _ADAPTER_MODULES[adapter_name]
    manifest = module.manifest()
    assert isinstance(manifest, AdapterManifest)
    assert CoverageDomain.NETWORK in manifest.coverage_domain
    assert manifest.id
    assert manifest.version
    assert manifest.upstream.name
    assert manifest.upstream.version
    assert manifest.upstream.digest
    assert manifest.risk_class in RiskClass
    assert manifest.license
    assert manifest.parser
    assert manifest.digest  # computed


def test_nmap_manifest_marks_gpl_and_independent_process() -> None:
    """nmap is GPL-licensed (§8.2) and MUST be invoked as an independent
    subprocess, not embedded as a library. The manifest carries both facts:
    `license == "GPL"` and an `independent_process` marker in `permissions`.
    """
    m = nmap.manifest()
    assert m.id == "nmap"
    assert m.upstream.name == "nmap"
    assert m.license.upper().startswith("GPL"), (
        "nmap manifest must declare a GPL license (§8.2: GPL tools are "
        "called as independent subprocesses, never embedded as libraries)"
    )
    assert "independent_process" in m.permissions, (
        "nmap manifest must mark independent_process=True via permissions"
    )
    # nmap sends probes; risk class LOW or ACTIVE (default LOW for -sV/-sC).
    assert m.risk_class in (RiskClass.LOW, RiskClass.ACTIVE)


def test_nuclei_tcp_manifest_specifics() -> None:
    m = nuclei_tcp.manifest()
    assert m.id == "nuclei_tcp"
    assert m.upstream.name == "nuclei"
    assert m.risk_class in (RiskClass.LOW, RiskClass.ACTIVE)


# ---------------------------------------------------------------------------
# nmap parser tests (XML -oX: host/port/service/script elements)
# ---------------------------------------------------------------------------


def test_nmap_positive_parse() -> None:
    raw = _fixture_path("nmap", "positive.xml").read_text(encoding="utf-8")
    observations = nmap.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) >= 1
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.NETWORK
    # asset_identity is ip:port per §8.2 network domain contract.
    assert ":" in obs.asset_identity, "nmap asset_identity must be ip:port"
    # raw must preserve service info so audit/replay can reconstruct the scan.
    assert obs.raw  # non-empty raw
    # At least one Observation surfaces a service name (e.g. ssh/http).
    has_service = any(
        "service" in o.raw or "name" in o.raw.get("service", {}) for o in observations
    )
    assert has_service, "nmap parser must surface service name in raw"


def test_nmap_nse_script_surfaces_cve_when_present() -> None:
    """An NSE vuln script (e.g. ssl-heartbleed) that emits a CVE in its
    output must populate the Observation's `cve` tuple so CoverageMatrix can
    credit the corresponding network coverage item.
    """
    raw = _fixture_path("nmap", "positive.xml").read_text(encoding="utf-8")
    observations = nmap.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    # Find any observation whose raw carries an NSE script.
    nse_obs = [o for o in observations if o.raw.get("script_id") or o.raw.get("scripts")]
    if nse_obs:
        # At least one NSE finding must surface a CVE or CWE.
        has_vuln = any(o.cve or o.cwe for o in nse_obs)
        assert has_vuln, (
            "nmap NSE vuln scripts must populate cve/cwe when script output "
            "references a CVE"
        )


def test_nmap_negative_parse_returns_empty() -> None:
    raw = _fixture_path("nmap", "negative.xml").read_text(encoding="utf-8")
    observations = nmap.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_nmap_malformed_parse_returns_empty() -> None:
    raw = _fixture_path("nmap", "malformed.xml").read_text(encoding="utf-8")
    observations = nmap.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


# ---------------------------------------------------------------------------
# nuclei_tcp parser tests (TCP/dns/ssl template matches)
# ---------------------------------------------------------------------------


def test_nuclei_tcp_positive_parse() -> None:
    raw = _fixture_path("nuclei_tcp", "positive.jsonl").read_text(encoding="utf-8")
    observations = nuclei_tcp.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) >= 1
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.NETWORK
    assert obs.asset_identity  # host or ip:port
    # nuclei TCP templates carry tags (dns/ssl/tcp) and references; the
    # parser must surface at least one cwe/cve across the positive fixture
    # so CoverageMatrix can credit network-layer coverage.
    has_mapped = any(o.cwe or o.cve for o in observations)
    assert has_mapped, (
        "nuclei_tcp parser must surface cwe/cve from template tags/references"
    )


def test_nuclei_tcp_negative_parse_returns_empty() -> None:
    raw = _fixture_path("nuclei_tcp", "negative.jsonl").read_text(encoding="utf-8")
    observations = nuclei_tcp.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_nuclei_tcp_malformed_parse_returns_empty() -> None:
    raw = _fixture_path("nuclei_tcp", "malformed.jsonl").read_text(encoding="utf-8")
    observations = nuclei_tcp.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


# ---------------------------------------------------------------------------
# Runner-level tests (timeout / scope_deny) - one per adapter
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
    targets = ("https://example.com/",)
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
    out_of_scope_target = ("https://evil-not-approved.test/",)
    adapter_input = _adapter_input(
        scope_snapshot, targets=out_of_scope_target, options={"ports": [443]}
    )
    with pytest.raises(ScopeDeniedError):
        runner.run(manifest, adapter_input)
    assert executor.calls == [], "container executed despite scope denial"
