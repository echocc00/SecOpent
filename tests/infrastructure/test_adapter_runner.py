"""TDD tests for AdapterRunner (§8.1, §8.4, M1 Task 8).

These tests exercise the AdapterRunner contract surface while mocking the
ContainerExecutor so they run on hosts without Docker (real Docker E2E is M5).

Scope enforcement uses the M0 PolicyEngine.evaluate and is the security gate
that must block out-of-scope targets BEFORE any container is invoked.
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
    AdapterUpstream,
    CoverageDomain,
    ExecutionPolicy,
    Observation,
    OutputStatus,
    Severity,
)
from secopent.domain.common.errors import DomainError
from secopent.domain.policy.engine import evaluate as policy_evaluate
from secopent.domain.policy.models import (
    ActionRequest,
    ExecutionMode,
    RiskClass,
)
from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot
from secopent.infrastructure.adapters.base import (
    AdapterRunner,
    ContainerResult,
    ScopeDeniedError,
)

# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


@dataclass
class FakeCASStore:
    """Records calls and returns predictable storage URIs."""

    base_dir: Path
    calls: list[tuple[str, bytes]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.calls is None:
            self.calls = []

    def store(self, content: bytes, *, kind: str) -> str:
        import hashlib

        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        self.calls.append((digest, content))
        return f"cas://{kind}/{digest}"


class RecordingExecutor:
    """Mock ContainerExecutor that records call args and returns canned output.

    Implements the ContainerExecutor Protocol structurally; tests inspect
    `calls` to verify security flags and digest pinning.
    """

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
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scope_snapshot() -> ScopeSnapshot:
    return ScopeSnapshot(
        id="snap-1",
        project_id="proj-1",
        include=("https://example.com", "10.0.0.0/24"),
        exclude=(),
        ports=(80, 443),
        limits=ScopeLimits(requests_per_second=5.0, concurrency=3, max_requests=50_000),
        approved_by="analyst",
        approved_at=datetime(2026, 1, 1, tzinfo=UTC),
        digest="sha256:" + "0" * 64,
    )


def _scope_dict(scope_snapshot: ScopeSnapshot) -> dict[str, object]:
    return {
        "id": scope_snapshot.id,
        "project_id": scope_snapshot.project_id,
        "include": scope_snapshot.include,
        "exclude": scope_snapshot.exclude,
        "ports": scope_snapshot.ports,
        "limits": {
            "requests_per_second": scope_snapshot.limits.requests_per_second,
            "concurrency": scope_snapshot.limits.concurrency,
            "max_requests": scope_snapshot.limits.max_requests,
        },
        "approved_by": scope_snapshot.approved_by,
        "approved_at": scope_snapshot.approved_at.isoformat(),
        "digest": scope_snapshot.digest,
        "cloud_accounts": scope_snapshot.cloud_accounts,
    }


@pytest.fixture
def in_scope_input(scope_snapshot: ScopeSnapshot) -> AdapterInput:
    return AdapterInput(
        run_id="run-1",
        engagement_id="eng-1",
        scope_snapshot=_scope_dict(scope_snapshot),
        targets=("https://example.com/",),
        options={"ports": [80, 443]},
        execution_policy=ExecutionPolicy(
            timeout_seconds=60, max_concurrency=2, network_profile="scoped-egress"
        ),
    )


@pytest.fixture
def out_of_scope_input(scope_snapshot: ScopeSnapshot) -> AdapterInput:
    return AdapterInput(
        run_id="run-2",
        engagement_id="eng-1",
        scope_snapshot=_scope_dict(scope_snapshot),
        targets=("https://outside.test/",),  # outside scope
        options={"ports": [80]},
        execution_policy=ExecutionPolicy(
            timeout_seconds=60, max_concurrency=2, network_profile="scoped-egress"
        ),
    )


@pytest.fixture
def manifest() -> AdapterManifest:
    return AdapterManifest(
        id="nmap-adapter",
        version="1.0.0",
        adapter_api_version="v1",
        license="Apache-2.0",
        upstream=AdapterUpstream(
            name="nmap",
            url="https://nmap.org",
            version="7.94",
            digest="sha256:abcdef0123456789",
        ),
        risk_class=RiskClass.ACTIVE,
        coverage_domain=(CoverageDomain.NETWORK,),
        input_schema="schema://nmap/input.json",
        output_schema="schema://nmap/output.json",
        network_policy="scoped-egress",
        parser="secopent_adapters.nmap:parse",
        fixtures=("fixtures/nmap/sample.xml",),
        permissions=("network.connect",),
    )


@pytest.fixture
def parser_registry() -> dict[str, Any]:
    """Parser registry mapping parser entrypoint string -> callable.

    The parser takes raw stdout bytes and the AdapterSource and returns a
    tuple of Observation records.
    """

    def parse_nmap(
        stdout: str, source: AdapterSource, artifacts: dict[str, bytes]
    ) -> tuple[Observation, ...]:
        return (
            Observation(
                external_id="obs-1",
                asset_identity="https://example.com/",
                source=source,
                rule_id="nmap-service",
                rule_version="7.94",
                coverage_domain=CoverageDomain.NETWORK,
                title="open port 80",
                severity=Severity.INFO,
                confidence=0.95,
                cwe=("CWE-200",),
                cve=("CVE-2024-9999",),
                owasp=("A05",),
            ),
        )

    return {"secopent_adapters.nmap:parse": parse_nmap}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_run_executes_container_and_returns_output(
    manifest: AdapterManifest,
    in_scope_input: AdapterInput,
    parser_registry: dict[str, Any],
    tmp_path: Path,
) -> None:
    executor = RecordingExecutor(
        stdout='{"host": "https://example.com/", "port": 80}',
        artifacts={"scan.json": b'{"port": 80}'},
    )
    cas = FakeCASStore(base_dir=tmp_path)
    runner = AdapterRunner(
        executor=executor,
        policy_engine=policy_evaluate,
        cas_store=cas,
        parser_registry=parser_registry,
    )

    output = runner.run(manifest, in_scope_input)

    assert output.run_id == "run-1"
    assert output.status is OutputStatus.COMPLETED
    assert len(executor.calls) == 1
    assert len(output.observations) == 1
    assert output.observations[0].external_id == "obs-1"


def test_scope_enforcement_blocks_out_of_scope(
    manifest: AdapterManifest,
    out_of_scope_input: AdapterInput,
    parser_registry: dict[str, Any],
    tmp_path: Path,
) -> None:
    executor = RecordingExecutor(stdout="ignored")
    cas = FakeCASStore(base_dir=tmp_path)
    runner = AdapterRunner(
        executor=executor,
        policy_engine=policy_evaluate,
        cas_store=cas,
        parser_registry=parser_registry,
    )

    with pytest.raises(ScopeDeniedError):
        runner.run(manifest, out_of_scope_input)

    # Security gate: container must NOT execute when scope denies the target.
    assert executor.calls == [], "container executed despite scope denial"


def test_scope_enforcement_uses_m0_policy_engine(
    manifest: AdapterManifest,
    in_scope_input: AdapterInput,
    parser_registry: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = RecordingExecutor(
        stdout="{}",
        artifacts={},
    )
    cas = FakeCASStore(base_dir=tmp_path)
    captured: list[ActionRequest] = []

    def spy_evaluate(
        request: ActionRequest,
        *,
        scope: Any,
        mode: ExecutionMode,
        approved_risks: frozenset[RiskClass],
        approved_capabilities: frozenset[str],
    ) -> Any:
        captured.append(request)
        from secopent.domain.policy.models import PolicyDecision

        return PolicyDecision(allowed=True, reason="ALLOWED")

    runner = AdapterRunner(
        executor=executor,
        policy_engine=spy_evaluate,
        cas_store=cas,
        parser_registry=parser_registry,
    )

    runner.run(manifest, in_scope_input)

    assert len(captured) == 1
    req = captured[0]
    assert req.target == "https://example.com/"
    assert req.port in (0, 80, 443)  # port derived from manifest/options
    assert req.risk is RiskClass.ACTIVE
    assert req.capability in manifest.permissions


def test_artifacts_uploaded_to_cas(
    manifest: AdapterManifest,
    in_scope_input: AdapterInput,
    parser_registry: dict[str, Any],
    tmp_path: Path,
) -> None:
    executor = RecordingExecutor(
        stdout="{}",
        artifacts={"scan.json": b"raw-scan-bytes"},
    )
    cas = FakeCASStore(base_dir=tmp_path)
    runner = AdapterRunner(
        executor=executor,
        policy_engine=policy_evaluate,
        cas_store=cas,
        parser_registry=parser_registry,
    )

    output = runner.run(manifest, in_scope_input)

    assert len(output.artifacts) == 1
    art = output.artifacts[0]
    assert art.sha256.startswith("sha256:")
    assert art.sha256 == cas.calls[0][0]
    assert art.storage_uri.startswith("cas://")
    # Artifact content is reproducibly hashed.
    import hashlib

    assert art.sha256 == "sha256:" + hashlib.sha256(b"raw-scan-bytes").hexdigest()


def test_observations_normalized(
    manifest: AdapterManifest,
    in_scope_input: AdapterInput,
    parser_registry: dict[str, Any],
    tmp_path: Path,
) -> None:
    executor = RecordingExecutor(
        stdout="raw-stdout",
        artifacts={},
    )
    cas = FakeCASStore(base_dir=tmp_path)
    runner = AdapterRunner(
        executor=executor,
        policy_engine=policy_evaluate,
        cas_store=cas,
        parser_registry=parser_registry,
    )

    output = runner.run(manifest, in_scope_input)

    assert len(output.observations) == 1
    obs = output.observations[0]
    assert obs.cwe == ("CWE-200",)
    assert obs.cve == ("CVE-2024-9999",)
    assert obs.owasp == ("A05",)
    assert obs.coverage_domain is CoverageDomain.NETWORK
    assert obs.severity is Severity.INFO
    # AdapterSource carries manifest identity.
    assert obs.source.name == manifest.id
    assert obs.source.version == manifest.version


def test_container_security_flags(
    manifest: AdapterManifest,
    in_scope_input: AdapterInput,
    parser_registry: dict[str, Any],
    tmp_path: Path,
) -> None:
    executor = RecordingExecutor(stdout="{}", artifacts={})
    cas = FakeCASStore(base_dir=tmp_path)
    runner = AdapterRunner(
        executor=executor,
        policy_engine=policy_evaluate,
        cas_store=cas,
        parser_registry=parser_registry,
    )

    runner.run(manifest, in_scope_input)

    assert len(executor.calls) == 1
    call = executor.calls[0]
    # Container security hardening (§8.4 Scoped Egress).
    security_flags = call["command"]
    assert "--user=nonroot" in security_flags
    assert "--cap-drop=ALL" in security_flags
    assert "--read-only" in security_flags
    assert "--network=scoped-egress" in security_flags
    assert call["network_policy"] == "scoped-egress"


def test_digest_pinned_image(
    manifest: AdapterManifest,
    in_scope_input: AdapterInput,
    parser_registry: dict[str, Any],
    tmp_path: Path,
) -> None:
    executor = RecordingExecutor(stdout="{}", artifacts={})
    cas = FakeCASStore(base_dir=tmp_path)
    runner = AdapterRunner(
        executor=executor,
        policy_engine=policy_evaluate,
        cas_store=cas,
        parser_registry=parser_registry,
    )

    runner.run(manifest, in_scope_input)

    assert len(executor.calls) == 1
    call = executor.calls[0]
    # Must use the pinned upstream digest, not a floating tag.
    assert call["image_digest"] == manifest.upstream.digest
    assert call["image_digest"].startswith("sha256:")


def test_execution_failure_returns_partial_output(
    manifest: AdapterManifest,
    in_scope_input: AdapterInput,
    parser_registry: dict[str, Any],
    tmp_path: Path,
) -> None:
    executor = RecordingExecutor(raise_on_call=RuntimeError("container died"))
    cas = FakeCASStore(base_dir=tmp_path)
    runner = AdapterRunner(
        executor=executor,
        policy_engine=policy_evaluate,
        cas_store=cas,
        parser_registry=parser_registry,
    )

    output = runner.run(manifest, in_scope_input)

    assert output.status is OutputStatus.FAILED
    assert output.run_id == "run-1"
    assert len(output.errors) >= 1
    assert any("container died" in err for err in output.errors)
    assert output.observations == ()


def test_scope_denied_error_is_domain_error() -> None:
    """ScopeDeniedError must subclass DomainError so the error layer can
    classify it consistently with the rest of the domain."""
    assert issubclass(ScopeDeniedError, DomainError)


def test_default_executor_is_subprocess(tmp_path: Path) -> None:
    """With no executor injected, the runner uses the real subprocess executor."""
    from secopent.infrastructure.adapters.subprocess_executor import (
        SubprocessContainerExecutor,
    )

    runner = AdapterRunner(
        policy_engine=policy_evaluate,
        cas_store=FakeCASStore(base_dir=tmp_path),
        parser_registry={},
    )
    assert isinstance(runner._executor, SubprocessContainerExecutor)


def test_create_production_runner_wires_subprocess(tmp_path: Path) -> None:
    """The production factory wires the real subprocess executor."""
    from secopent.infrastructure.adapters.base import create_production_runner
    from secopent.infrastructure.adapters.subprocess_executor import (
        SubprocessContainerExecutor,
    )

    runner = create_production_runner(
        policy_engine=policy_evaluate,
        cas_store=FakeCASStore(base_dir=tmp_path),
        parser_registry={},
    )
    assert isinstance(runner._executor, SubprocessContainerExecutor)


# ---------------------------------------------------------------------------
# Cloud-target scope routing (M1 Task 12, §4.1.1 方案 B)
# ---------------------------------------------------------------------------


@pytest.fixture
def cloud_scope_snapshot() -> ScopeSnapshot:
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


@pytest.fixture
def cloud_manifest() -> AdapterManifest:
    return AdapterManifest(
        id="prowler",
        version="1.0.0",
        adapter_api_version="v1",
        license="Apache-2.0",
        upstream=AdapterUpstream(
            name="prowler",
            url="https://github.com/prowler-cloud/prowler",
            version="4.6.0",
            digest="sha256:prowler-4.6.0",
        ),
        risk_class=RiskClass.PASSIVE,
        coverage_domain=(CoverageDomain.CLOUD,),
        input_schema="schema://prowler/input.json",
        output_schema="schema://prowler/output.json",
        network_policy="scoped-egress",
        parser="secopent_adapters.prowler:parse",
        permissions=("passive",),
    )


def _cloud_input(scope: ScopeSnapshot, targets: tuple[str, ...]) -> AdapterInput:
    return AdapterInput(
        run_id="run-cloud",
        engagement_id="eng-1",
        scope_snapshot=_scope_dict(scope),
        targets=targets,
        options={},
        execution_policy=ExecutionPolicy(
            timeout_seconds=60, max_concurrency=2, network_profile="scoped-egress"
        ),
    )


def test_cloud_target_in_scope_executes_container(
    cloud_manifest: AdapterManifest,
    cloud_scope_snapshot: ScopeSnapshot,
    tmp_path: Path,
) -> None:
    """An in-scope cloud-account target must pass the scope gate WITHOUT any
    URL/port check (cloud accounts are not URLs) and execute the container."""
    executor = RecordingExecutor(stdout="[]", artifacts={})
    cas = FakeCASStore(base_dir=tmp_path)
    runner = AdapterRunner(
        executor=executor,
        policy_engine=policy_evaluate,
        cas_store=cas,
        parser_registry={},
    )

    output = runner.run(cloud_manifest, _cloud_input(cloud_scope_snapshot, ("aws:123456789012",)))

    assert output.status is OutputStatus.COMPLETED
    assert len(executor.calls) == 1


def test_cloud_target_out_of_scope_denied_before_container(
    cloud_manifest: AdapterManifest,
    cloud_scope_snapshot: ScopeSnapshot,
    tmp_path: Path,
) -> None:
    """An out-of-scope cloud-account target must be denied before the container
    runs - the cloud scope gate is a security boundary."""
    executor = RecordingExecutor(stdout="should-not-run")
    cas = FakeCASStore(base_dir=tmp_path)
    runner = AdapterRunner(
        executor=executor,
        policy_engine=policy_evaluate,
        cas_store=cas,
        parser_registry={},
    )

    with pytest.raises(ScopeDeniedError):
        runner.run(
            cloud_manifest,
            _cloud_input(cloud_scope_snapshot, ("aws:999999999999",)),
        )

    assert executor.calls == [], "container executed despite cloud scope denial"


def test_cloud_target_normalizes_before_scope_check(
    cloud_manifest: AdapterManifest,
    cloud_scope_snapshot: ScopeSnapshot,
    tmp_path: Path,
) -> None:
    """Provider casing/whitespace on the target must not defeat the scope match."""
    executor = RecordingExecutor(stdout="[]", artifacts={})
    cas = FakeCASStore(base_dir=tmp_path)
    runner = AdapterRunner(
        executor=executor,
        policy_engine=policy_evaluate,
        cas_store=cas,
        parser_registry={},
    )

    output = runner.run(
        cloud_manifest, _cloud_input(cloud_scope_snapshot, ("AWS:123456789012",))
    )
    assert output.status is OutputStatus.COMPLETED


def test_destructive_cloud_target_denied(
    cloud_manifest: AdapterManifest,
    cloud_scope_snapshot: ScopeSnapshot,
    tmp_path: Path,
) -> None:
    """A DESTRUCTIVE cloud adapter is denied even for an in-scope account,
    mirroring the PolicyEngine decision order (Destructive first)."""
    import dataclasses

    destructive = dataclasses.replace(cloud_manifest, risk_class=RiskClass.DESTRUCTIVE)
    executor = RecordingExecutor(stdout="should-not-run")
    cas = FakeCASStore(base_dir=tmp_path)
    runner = AdapterRunner(
        executor=executor,
        policy_engine=policy_evaluate,
        cas_store=cas,
        parser_registry={},
    )

    with pytest.raises(ScopeDeniedError):
        runner.run(
            destructive, _cloud_input(cloud_scope_snapshot, ("aws:123456789012",))
        )
    assert executor.calls == []
