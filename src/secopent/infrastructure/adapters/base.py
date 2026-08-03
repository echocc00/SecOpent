"""AdapterRunner: container execution + scope enforcement + artifact CAS (§8.1, §8.4).

The runner is the single integration point between the adapter contract layer
(domain/adapters/contracts.py) and the outside world. It enforces three
invariants in order:

1. **Scope gate first.** For every target in `AdapterInput.targets`, an
   `ActionRequest` is constructed from the manifest's `risk_class` and
   `permissions` (capability) plus the per-target port, then handed to
   `PolicyEngine.evaluate`. Any denial raises `ScopeDeniedError` and NO
   container is executed. This is the security gate - it must run before
   anything that touches Docker.
2. **Pinned-image container execution.** The executor is invoked with the
   manifest's `upstream.digest` (never a floating tag) plus the §8.4
   security flags: `--user=nonroot --cap-drop=ALL --read-only
   --network=scoped-egress`.
3. **Artifact normalization.** Each artifact emitted by the container is
   sha256-hashed, stored in CAS, and surfaced as an `Artifact` handle. The
   manifest parser is invoked on stdout to produce normalized
   `Observation` records.

`ContainerExecutor` is a Protocol so tests inject a mock and the production
subprocess-based implementation (not exercised here - Docker is M5) can be
swapped in without touching the runner.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from secopent.domain.adapters.contracts import (
    AdapterInput,
    AdapterManifest,
    AdapterOutput,
    AdapterSource,
    Artifact,
    CoverageDomain,
    Observation,
    OutputStatus,
)
from secopent.domain.common.errors import DomainError, DomainValidationError
from secopent.domain.policy.models import (
    ActionRequest,
    ExecutionMode,
    PolicyDecision,
    RiskClass,
)
from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot
from secopent.domain.scope.normalize import normalize_cloud_account


class ScopeDeniedError(DomainError):
    """Raised when the scope gate denies a target before execution.

    Subclasses `DomainError` so the error layer can classify scope failures
    alongside other deterministic domain errors.
    """


# ---------------------------------------------------------------------------
# ContainerExecutor Protocol + result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ContainerResult:
    """Output of a single container invocation.

    `artifacts_dir` points to a directory the executor populated with raw
    artifact files; the runner reads and hashes them into CAS.
    """

    stdout: str
    stderr: str
    exit_code: int
    artifacts_dir: Path


@runtime_checkable
class ContainerExecutor(Protocol):
    """Injectable container execution surface.

    The production implementation (M5, real Docker) reads `image_digest`,
    applies the security flags carried in `command`, mounts `mounts`, and
    applies `network_policy` + `resource_limits`. Tests provide a mock that
    records the call and returns a canned `ContainerResult`.
    """

    def run(
        self,
        *,
        image_digest: str,
        command: Sequence[str],
        mounts: Mapping[str, str],
        network_policy: str,
        resource_limits: Mapping[str, Any],
        extra_labels: Mapping[str, str] = ...,
        env: Mapping[str, str] = ...,
    ) -> ContainerResult: ...


# ---------------------------------------------------------------------------
# CAS Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class CASStore(Protocol):
    """Content-addressed store for adapter artifacts.

    `store(content, kind=...)` returns a stable `cas://` URI keyed by the
    content's sha256. The runner computes the digest itself so it can attach
    it to the `Artifact` handle without re-reading from CAS.
    """

    def store(self, content: bytes, *, kind: str) -> str: ...


# ---------------------------------------------------------------------------
# PolicyEngine callable type
# ---------------------------------------------------------------------------

# Mirrors the signature of secopent.domain.policy.engine.evaluate so the
# runner can accept either the real engine or a test spy.
PolicyEngineFn = Callable[..., PolicyDecision]


# ---------------------------------------------------------------------------
# AdapterRunner
# ---------------------------------------------------------------------------


# §8.4 Scoped Egress container hardening flags. These are passed via the
# `command` argument to the executor so the production Docker invocation can
# translate them into `docker run` flags, and tests can assert on them.
_SECURITY_FLAGS: tuple[str, ...] = (
    "--user=nonroot",
    "--cap-drop=ALL",
    "--read-only",
    "--network=scoped-egress",
)

# Default per-container resource limits (§8.4). Tunable via future config.
_DEFAULT_RESOURCE_LIMITS: dict[str, Any] = {
    "cpu_quota": "1.0",
    "memory_mb": 512,
    "pids_limit": 64,
    "no_new_privileges": True,
}


class AdapterRunner:
    """Runs an AdapterManifest against an AdapterInput.

    The runner is stateless across runs; all per-run state lives in the
    inputs and outputs. Dependencies (executor, policy_engine, cas_store,
    parser_registry) are injected so each is replaceable in tests.

    If no ``executor`` is supplied, the production
    :class:`SubprocessContainerExecutor` (real ``docker run``) is used. Tests
    inject a mock executor. NOTE (Phase A): the production executor expects
    digest-pinned image refs and a clean tool command; wiring the manifest's
    image refs (IMAGE_CATALOG) and command format through the runner is
    completed in A3 - unit tests here use the mock executor.
    """

    def __init__(
        self,
        *,
        executor: ContainerExecutor | None = None,
        policy_engine: PolicyEngineFn,
        cas_store: CASStore,
        parser_registry: Mapping[str, Callable[..., tuple[Observation, ...]]],
    ) -> None:
        if executor is None:
            from .subprocess_executor import SubprocessContainerExecutor

            executor = SubprocessContainerExecutor()
        self._executor = executor
        self._policy_engine = policy_engine
        self._cas = cas_store
        self._parsers = dict(parser_registry)

    def run(
        self,
        manifest: AdapterManifest,
        adapter_input: AdapterInput,
    ) -> AdapterOutput:
        """Execute the adapter and return a normalized AdapterOutput.

        Steps:
            1. Rebuild the ScopeSnapshot from the input's serialized form.
            2. For each target, build an ActionRequest and call
               PolicyEngine.evaluate. Any denial raises ScopeDeniedError
               BEFORE the container is invoked.
            3. Execute the container with the pinned image digest and §8.4
               security flags.
            4. Collect artifacts from the artifacts dir, sha256-hash them,
               and store them in CAS.
            5. Invoke the manifest parser on stdout to produce Observation
               records.
            6. Return AdapterOutput (COMPLETED on exit 0, FAILED on
               executor exception; PARTIAL is reserved for parser-level
               partial-success and is not produced here yet).
        """
        scope = _rebuild_scope_snapshot(adapter_input.scope_snapshot)
        _enforce_scope(
            manifest=manifest,
            adapter_input=adapter_input,
            scope=scope,
            policy_engine=self._policy_engine,
        )

        source = AdapterSource(
            name=manifest.id,
            version=manifest.version,
            template_version=manifest.upstream.version,
        )

        try:
            result = self._execute_container(manifest, adapter_input)
        except Exception as exc:  # noqa: BLE001 - runner reports any exec failure
            return AdapterOutput(
                run_id=adapter_input.run_id,
                status=OutputStatus.FAILED,
                tool=source,
                errors=(f"container execution failed: {exc}",),
            )

        artifacts = self._collect_artifacts(result.artifacts_dir)

        observations = self._parse(
            manifest=manifest,
            source=source,
            stdout=result.stdout,
            artifacts_dir=result.artifacts_dir,
        )

        status = (
            OutputStatus.COMPLETED if result.exit_code == 0 else OutputStatus.PARTIAL
        )
        errors: tuple[str, ...] = ()
        if result.exit_code != 0:
            errors = (f"container exit_code={result.exit_code} stderr={result.stderr}",)

        return AdapterOutput(
            run_id=adapter_input.run_id,
            status=status,
            tool=source,
            artifacts=tuple(artifacts),
            observations=observations,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Internal steps
    # ------------------------------------------------------------------

    def _execute_container(
        self,
        manifest: AdapterManifest,
        adapter_input: AdapterInput,
    ) -> ContainerResult:
        """Invoke the executor with pinned image + §8.4 security flags."""
        import tempfile

        out_dir = Path(tempfile.mkdtemp(prefix="adapter-out-"))
        in_dir = Path(tempfile.mkdtemp(prefix="adapter-in-"))
        input_payload = {
            "run_id": adapter_input.run_id,
            "engagement_id": adapter_input.engagement_id,
            "targets": list(adapter_input.targets),
            "options": adapter_input.options,
            "execution_policy": {
                "timeout_seconds": adapter_input.execution_policy.timeout_seconds,
                "max_concurrency": adapter_input.execution_policy.max_concurrency,
                "network_profile": adapter_input.execution_policy.network_profile,
            },
        }
        (in_dir / "input.json").write_text(
            json.dumps(input_payload), encoding="utf-8"
        )

        command: list[str] = list(_SECURITY_FLAGS) + [
            manifest.upstream.digest,
            "--input=/in/input.json",
            "--output=/out",
        ]

        mounts = {"/in": str(in_dir), "/out": str(out_dir)}
        return self._executor.run(
            image_digest=manifest.upstream.digest,
            command=command,
            mounts=mounts,
            network_policy=manifest.network_policy,
            resource_limits=dict(_DEFAULT_RESOURCE_LIMITS),
        )

    def _collect_artifacts(self, artifacts_dir: Path) -> list[Artifact]:
        """Hash every file in artifacts_dir and store it in CAS."""
        artifacts: list[Artifact] = []
        if not artifacts_dir.exists():
            return artifacts
        for path in sorted(artifacts_dir.iterdir()):
            if not path.is_file():
                continue
            content = path.read_bytes()
            digest = "sha256:" + hashlib.sha256(content).hexdigest()
            storage_uri = self._cas.store(content, kind=path.suffix.lstrip(".") or "bin")
            artifacts.append(
                Artifact(
                    id=path.name,
                    kind=path.suffix.lstrip(".") or "bin",
                    sha256=digest,
                    storage_uri=storage_uri,
                )
            )
        return artifacts

    def _parse(
        self,
        *,
        manifest: AdapterManifest,
        source: AdapterSource,
        stdout: str,
        artifacts_dir: Path,
    ) -> tuple[Observation, ...]:
        """Invoke the manifest parser to normalize stdout into Observations."""
        parser = self._parsers.get(manifest.parser)
        if parser is None:
            return ()
        artifacts: dict[str, bytes] = {}
        if artifacts_dir.exists():
            for path in artifacts_dir.iterdir():
                if path.is_file():
                    artifacts[path.name] = path.read_bytes()
        return parser(stdout=stdout, source=source, artifacts=artifacts)


# ---------------------------------------------------------------------------
# Production runner factory
# ---------------------------------------------------------------------------


def create_production_runner(
    *,
    policy_engine: PolicyEngineFn,
    cas_store: CASStore,
    parser_registry: Mapping[str, Callable[..., tuple[Observation, ...]]],
) -> AdapterRunner:
    """Build an AdapterRunner wired to the real SubprocessContainerExecutor.

    The production execution path runs digest-pinned tool containers under the
    §8.4 hardening flags. (Phase A: the manifest image-ref / command wiring
    through the runner is completed in A3.)
    """
    from .subprocess_executor import SubprocessContainerExecutor

    return AdapterRunner(
        executor=SubprocessContainerExecutor(),
        policy_engine=policy_engine,
        cas_store=cas_store,
        parser_registry=parser_registry,
    )


# ---------------------------------------------------------------------------
# Scope enforcement helpers
# ---------------------------------------------------------------------------


def _rebuild_scope_snapshot(serialized: Mapping[str, object]) -> ScopeSnapshot:
    """Rebuild a ScopeSnapshot from the dict form carried in AdapterInput.

    AdapterInput.scope_snapshot is intentionally a plain dict so the contract
    layer does not import ScopeSnapshot (keeping adapters decoupled from the
    scope lifecycle). The runner rebuilds the typed snapshot to call
    PolicyEngine.evaluate.
    """
    limits_raw = serialized["limits"]
    assert isinstance(limits_raw, Mapping), "scope_snapshot.limits must be a mapping"
    limits = ScopeLimits(
        requests_per_second=float(limits_raw["requests_per_second"]),
        concurrency=int(limits_raw["concurrency"]),
        max_requests=int(limits_raw["max_requests"]),
    )
    ports_raw = serialized["ports"]
    assert isinstance(ports_raw, Sequence), "scope_snapshot.ports must be a sequence"
    approved_at_raw = serialized["approved_at"]
    assert isinstance(approved_at_raw, str), "scope_snapshot.approved_at must be ISO str"
    include_raw = serialized["include"]
    assert isinstance(include_raw, Sequence), "scope_snapshot.include must be a sequence"
    exclude_raw = serialized.get("exclude", ())
    assert isinstance(exclude_raw, Sequence), "scope_snapshot.exclude must be a sequence"
    cloud_raw = serialized.get("cloud_accounts", ())
    assert isinstance(cloud_raw, Sequence), "scope_snapshot.cloud_accounts must be a sequence"
    return ScopeSnapshot(
        id=str(serialized["id"]),
        project_id=str(serialized["project_id"]),
        include=tuple(str(p) for p in include_raw),
        exclude=tuple(str(p) for p in exclude_raw),
        ports=tuple(int(p) for p in ports_raw),
        limits=limits,
        approved_by=str(serialized["approved_by"]),
        approved_at=_parse_iso(approved_at_raw),
        digest=str(serialized["digest"]),
        cloud_accounts=tuple(str(c) for c in cloud_raw),
    )


def _parse_iso(value: str) -> Any:
    """Parse an ISO-8601 timestamp; falls back to fromisoformat."""
    from datetime import datetime

    return datetime.fromisoformat(value)


def _enforce_scope(
    *,
    manifest: AdapterManifest,
    adapter_input: AdapterInput,
    scope: ScopeSnapshot,
    policy_engine: PolicyEngineFn,
) -> None:
    """Run the M0 PolicyEngine against every target; raise on any denial.

    Targets are routed by domain (§4.1.1 方案 B):

    - **Cloud targets** (manifest covers ``cloud`` AND the target is a
      ``provider:account_id`` string) are checked against the scope's
      ``cloud_accounts`` set - they are NOT URLs/ports, so they bypass the
      PolicyEngine's URL/port gate but keep the same Destructive -> scope ->
      risk -> capability decision order.
    - **Network targets** (URL/IP/domain) go through the injected
      PolicyEngine.evaluate as before.

    The capability is the manifest's first declared permission (the action
    the adapter is authorized to take, e.g. `network.connect`). Port is
    derived from the input options if present, else 0 (port-less passive
    recon). Risk class comes from the manifest.
    """
    capability = manifest.permissions[0] if manifest.permissions else "passive"
    ports = _extract_ports(adapter_input)
    risk = manifest.risk_class
    approved_risks = frozenset(
        {RiskClass.PASSIVE, RiskClass.LOW, RiskClass.ACTIVE, RiskClass.INTRUSIVE}
    )
    approved_capabilities = frozenset(manifest.permissions)

    for target in adapter_input.targets:
        if _is_cloud_target(target, manifest):
            _enforce_cloud_target(
                target=target,
                risk=risk,
                capability=capability,
                scope=scope,
                approved_risks=approved_risks,
                approved_capabilities=approved_capabilities,
            )
            continue
        port = ports[0] if ports else 0
        request = ActionRequest(
            target=target, port=port, risk=risk, capability=capability
        )
        decision = policy_engine(
            request,
            scope=scope,
            mode=ExecutionMode.SCOPE_AUTOPILOT,
            approved_risks=approved_risks,
            approved_capabilities=approved_capabilities,
        )
        if not decision.allowed:
            raise ScopeDeniedError(
                f"scope denied for target={target} reason={decision.reason}"
            )


def _is_cloud_target(target: str, manifest: AdapterManifest) -> bool:
    """A target is cloud-scoped when the manifest covers the cloud domain AND
    the target parses as a ``provider:account_id`` cloud account."""
    if CoverageDomain.CLOUD not in manifest.coverage_domain:
        return False
    try:
        normalize_cloud_account(target)
    except DomainValidationError:
        return False
    return True


def _enforce_cloud_target(
    *,
    target: str,
    risk: RiskClass,
    capability: str,
    scope: ScopeSnapshot,
    approved_risks: frozenset[RiskClass],
    approved_capabilities: frozenset[str],
) -> None:
    """Scope gate for cloud-account targets.

    Mirrors the PolicyEngine decision order (Destructive -> scope -> risk ->
    capability -> ALLOWED) but substitutes the cloud-account membership check
    for the URL/port check, since cloud accounts are not network endpoints.
    """
    if risk is RiskClass.DESTRUCTIVE:
        raise ScopeDeniedError(
            f"scope denied for target={target} reason=DESTRUCTIVE_ACTION_DENIED"
        )
    if not scope.includes_cloud_account(target):
        raise ScopeDeniedError(f"scope denied for target={target} reason=SCOPE_DENIED")
    if risk not in approved_risks:
        raise ScopeDeniedError(
            f"scope denied for target={target} reason=RISK_NOT_APPROVED"
        )
    if risk in {RiskClass.ACTIVE, RiskClass.INTRUSIVE} and (
        capability not in approved_capabilities
    ):
        raise ScopeDeniedError(
            f"scope denied for target={target} reason=CAPABILITY_NOT_APPROVED"
        )


def _extract_ports(adapter_input: AdapterInput) -> tuple[int, ...]:
    """Extract port tuple from the input options, if present."""
    ports_raw = adapter_input.options.get("ports")
    if not isinstance(ports_raw, Sequence):
        return ()
    return tuple(int(p) for p in ports_raw)
