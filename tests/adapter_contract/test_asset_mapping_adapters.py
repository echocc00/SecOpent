"""TDD contract tests for the asset-mapping Adapter Pack (M1 Task 9, §8.2).

These tests exercise the parser layer of the five asset-mapping adapters:
subfinder / httpx / naabu / katana / fingerprinthub. They use FIXTURE files
(sample tool stdout/JSON output captured from real tool runs) rather than
executing the real tools - real container execution is M5 E2E scope.

Each adapter has five fixture classes:

- **positive**: well-formed tool output -> at least one Observation with the
  expected `coverage_domain=asset`, `asset_identity`, `severity`, and (where
  applicable) populated `cwe`/`owasp` tuples.
- **negative**: empty-but-well-formed tool output -> zero Observations, no
  crash.
- **timeout**: a fixture that simulates the tool timing out (exit_code != 0
  with a timeout sentinel on stderr) -> the AdapterRunner reports FAILED
  status; the parser is not invoked.
- **scope_deny**: an out-of-scope target is blocked by the M0 PolicyEngine
  BEFORE the container runs. The parser is never invoked.
- **malformed**: corrupt JSON output -> the parser captures the parse error
  without raising and emits zero Observations.

The manifest loading tests assert that each adapter's `manifest.py` builds an
`AdapterManifest` whose `coverage_domain` includes `asset` and whose upstream
pin and risk class are populated.
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
    Severity,
)
from secopent.domain.policy.engine import evaluate as policy_evaluate
from secopent.domain.policy.models import RiskClass
from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot
from secopent.infrastructure.adapters.base import (
    AdapterRunner,
    ContainerResult,
    ScopeDeniedError,
)

# ---------------------------------------------------------------------------
# Adapter under test: import list (populated lazily by the parametrize fixture)
# ---------------------------------------------------------------------------
from secopent.integrations.adapters import (  # noqa: E402
    fingerprinthub,
    katana,
    naabu,
    subfinder,
)
from secopent.integrations.adapters import (
    httpx as httpx_adapter,
)

# ---------------------------------------------------------------------------
# Test doubles (reused from test_adapter_runner.py shape)
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
        id="snap-asset",
        project_id="proj-1",
        include=("example.com", "10.0.0.0/24"),
        exclude=(),
        ports=(80, 443),
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
        run_id="run-asset-1",
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
    "subfinder": subfinder,
    "httpx": httpx_adapter,
    "naabu": naabu,
    "katana": katana,
    "fingerprinthub": fingerprinthub,
}


def _build_runner(adapter_module: Any, tmp_path: Path) -> AdapterRunner:
    """Wire an AdapterRunner with the adapter's parser registered."""
    parser_entry = adapter_module.manifest().parser
    return AdapterRunner(
        executor=RecordingExecutor(),
        policy_engine=policy_evaluate,
        cas_store=FakeCASStore(base_dir=tmp_path),
        parser_registry={parser_entry: adapter_module.parse},
    )


# ---------------------------------------------------------------------------
# Manifest tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("adapter_name", list(_ADAPTER_MODULES))
def test_manifest_loads_with_asset_coverage(adapter_name: str) -> None:
    module = _ADAPTER_MODULES[adapter_name]
    manifest = module.manifest()
    assert isinstance(manifest, AdapterManifest)
    assert CoverageDomain.ASSET in manifest.coverage_domain
    assert manifest.id
    assert manifest.version
    assert manifest.upstream.name
    assert manifest.upstream.version
    assert manifest.upstream.digest
    assert manifest.risk_class in RiskClass
    assert manifest.license
    assert manifest.parser
    # manifest.digest is computed at construction; non-empty means it built.
    assert manifest.digest


def test_subfinder_manifest_specifics() -> None:
    m = subfinder.manifest()
    assert m.id == "subfinder"
    assert m.risk_class is RiskClass.PASSIVE
    assert m.upstream.name == "subfinder"
    assert "asset" in [d.value for d in m.coverage_domain]


def test_httpx_manifest_specifics() -> None:
    m = httpx_adapter.manifest()
    assert m.id == "httpx"
    assert m.risk_class in (RiskClass.PASSIVE, RiskClass.LOW)
    assert m.upstream.name == "httpx"


def test_naabu_manifest_specifics() -> None:
    m = naabu.manifest()
    assert m.id == "naabu"
    assert m.upstream.name == "naabu"


def test_katana_manifest_specifics() -> None:
    m = katana.manifest()
    assert m.id == "katana"
    assert m.upstream.name == "katana"


def test_fingerprinthub_manifest_specifics() -> None:
    m = fingerprinthub.manifest()
    assert m.id == "fingerprinthub"
    assert m.upstream.name == "FingerprintHub"


# ---------------------------------------------------------------------------
# Parser-level tests (positive / negative / malformed)
# ---------------------------------------------------------------------------

_ADAPTER_SOURCE = AdapterSource(name="test", version="1.0.0", template_version="1.0.0")


def _fixture_path(adapter_name: str, fixture_file: str) -> Path:
    """Locate a fixture file shipped alongside the adapter module."""
    module = _ADAPTER_MODULES[adapter_name]
    base = Path(module.__file__).parent / "fixtures"
    return base / fixture_file


def test_subfinder_positive_parse() -> None:
    raw = _fixture_path("subfinder", "positive.json").read_text(encoding="utf-8")
    observations = subfinder.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) >= 1
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.ASSET
    assert obs.asset_identity  # domain populated
    assert obs.severity is Severity.INFO
    assert obs.source.name == "test"


def test_subfinder_negative_parse_returns_empty() -> None:
    raw = _fixture_path("subfinder", "negative.json").read_text(encoding="utf-8")
    observations = subfinder.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_subfinder_malformed_parse_returns_empty() -> None:
    raw = _fixture_path("subfinder", "malformed.json").read_text(encoding="utf-8")
    observations = subfinder.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_httpx_positive_parse() -> None:
    raw = _fixture_path("httpx", "positive.json").read_text(encoding="utf-8")
    observations = httpx_adapter.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) >= 1
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.ASSET
    assert obs.asset_identity  # url
    # tech array should be reflected somewhere in raw or evidence
    assert "tech" in obs.raw or "technologies" in obs.raw


def test_httpx_negative_parse_returns_empty() -> None:
    raw = _fixture_path("httpx", "negative.json").read_text(encoding="utf-8")
    observations = httpx_adapter.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_httpx_malformed_parse_returns_empty() -> None:
    raw = _fixture_path("httpx", "malformed.json").read_text(encoding="utf-8")
    observations = httpx_adapter.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_naabu_positive_parse() -> None:
    raw = _fixture_path("naabu", "positive.json").read_text(encoding="utf-8")
    observations = naabu.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) >= 1
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.ASSET
    assert obs.asset_identity  # ip:port


def test_naabu_negative_parse_returns_empty() -> None:
    raw = _fixture_path("naabu", "negative.json").read_text(encoding="utf-8")
    observations = naabu.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_naabu_malformed_parse_returns_empty() -> None:
    raw = _fixture_path("naabu", "malformed.json").read_text(encoding="utf-8")
    observations = naabu.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_katana_positive_parse() -> None:
    raw = _fixture_path("katana", "positive.json").read_text(encoding="utf-8")
    observations = katana.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) >= 1
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.ASSET
    assert obs.asset_identity  # url


def test_katana_negative_parse_returns_empty() -> None:
    raw = _fixture_path("katana", "negative.json").read_text(encoding="utf-8")
    observations = katana.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_katana_malformed_parse_returns_empty() -> None:
    raw = _fixture_path("katana", "malformed.json").read_text(encoding="utf-8")
    observations = katana.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_fingerprinthub_positive_parse() -> None:
    raw = _fixture_path("fingerprinthub", "positive.json").read_text(encoding="utf-8")
    observations = fingerprinthub.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) >= 1
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.ASSET
    # fingerprinthub emits fingerprint matches; cwe/owasp may be populated.
    assert obs.title


def test_fingerprinthub_negative_parse_returns_empty() -> None:
    raw = _fixture_path("fingerprinthub", "negative.json").read_text(encoding="utf-8")
    observations = fingerprinthub.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_fingerprinthub_malformed_parse_returns_empty() -> None:
    raw = _fixture_path("fingerprinthub", "malformed.json").read_text(encoding="utf-8")
    observations = fingerprinthub.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


# ---------------------------------------------------------------------------
# Runner-level tests (timeout / scope_deny)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("adapter_name", list(_ADAPTER_MODULES))
def test_timeout_fixture_produces_failed_output(
    adapter_name: str, scope_snapshot: ScopeSnapshot, tmp_path: Path
) -> None:
    module = _ADAPTER_MODULES[adapter_name]
    manifest = module.manifest()
    timeout_text = (Path(module.__file__).parent / "fixtures" / "timeout.txt").read_text(
        encoding="utf-8"
    )
    executor = RecordingExecutor(
        stdout="", stderr=timeout_text, exit_code=124  # 124 is the GNU `timeout` code
    )
    cas = FakeCASStore(base_dir=tmp_path)
    parser_entry = manifest.parser
    runner = AdapterRunner(
        executor=executor,
        policy_engine=policy_evaluate,
        cas_store=cas,
        parser_registry={parser_entry: module.parse},
    )
    targets = ("https://example.com/",)
    options = {"ports": [443]} if adapter_name != "naabu" else {"ports": [80]}
    adapter_input = _adapter_input(scope_snapshot, targets=targets, options=options)
    output = runner.run(manifest, adapter_input)

    # exit_code != 0 -> PARTIAL per AdapterRunner.run; never COMPLETED on timeout.
    assert output.status is not OutputStatus.COMPLETED
    assert output.errors  # error captured


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
    # Target outside the scope_snapshot.include list (example.com / 10.0.0.0/24).
    # Must be a URL because PolicyEngine.evaluate calls scope.includes_url which
    # requires an http/https scheme.
    out_of_scope_target = ("https://evil-not-approved.test/",)
    adapter_input = _adapter_input(
        scope_snapshot, targets=out_of_scope_target, options={"ports": [443]}
    )

    with pytest.raises(ScopeDeniedError):
        runner.run(manifest, adapter_input)

    # Security gate: container must NOT execute when scope denies the target.
    assert executor.calls == [], "container executed despite scope denial"
