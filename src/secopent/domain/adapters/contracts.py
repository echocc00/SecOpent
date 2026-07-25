# src/secopent/domain/adapters/contracts.py
"""Adapter contracts for the four-domain tool execution plane (§8.1, §8.3).

Every Tool Adapter - asset recon, web/API, network/host, cloud/container - must
satisfy the same contract surface declared here:

- `AdapterManifest` (§8.1): declarative identity, upstream pinning, risk class,
  coverage domain, schema references, network policy, parser entrypoint,
  fixtures, and permissions. `digest` is a canonical digest of the manifest
  content (excluding the digest itself) so manifest integrity is verifiable.
- `AdapterInput`: run identity, engagement/assessment linkage, scope snapshot,
  targets, options, and an `ExecutionPolicy` (timeout/concurrency/profile).
- `AdapterOutput`: run identity, completion status, the `AdapterSource` that
  produced it, raw `Artifact` handles, normalized `Observation` records, and
  any parser errors.
- `Observation` (§8.3): the Faraday-style unified record. `cwe`/`cve`/`owasp`
  tuples feed the CoverageMatrix; `confidence` is a probability in [0, 1];
  `severity` and `coverage_domain` are enums so downstream logic never parses
  free text.

The schema is stdlib-only (frozen dataclasses + StrEnum) to keep the domain
layer free of framework coupling. Pydantic/SQLAlchemy live in infrastructure.
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields
from enum import StrEnum

from ..common.canonical import canonical_digest
from ..common.errors import DomainValidationError
from ..policy.models import RiskClass

# Confidence is a probability in [0.0, 1.0] (inclusive on both ends).
_CONFIDENCE_MIN: float = 0.0
_CONFIDENCE_MAX: float = 1.0


class Severity(StrEnum):
    """Observation severity buckets (§8.3).

    Order matches risk escalation; the enum values are the canonical strings
    used in serialized output and in downstream policy rules.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CoverageDomain(StrEnum):
    """The four execution domains an Observation or Adapter can target."""

    ASSET = "asset"
    WEB = "web"
    NETWORK = "network"
    CLOUD = "cloud"


class OutputStatus(StrEnum):
    """Adapter run completion status."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class AdapterSource:
    """Identity of the tool/template revision that emitted an Observation.

    `template_version` covers template-driven tools (e.g. nuclei templates)
    where the engine version and the rule template version move independently.
    """

    name: str
    version: str
    template_version: str

    def __post_init__(self) -> None:
        if not self.name:
            raise DomainValidationError("AdapterSource.name must be non-empty")
        if not self.version:
            raise DomainValidationError("AdapterSource.version must be non-empty")
        if not self.template_version:
            raise DomainValidationError(
                "AdapterSource.template_version must be non-empty"
            )


@dataclass(frozen=True, slots=True)
class AdapterUpstream:
    """Pinned upstream tool the Adapter wraps.

    `digest` is the upstream artifact digest (e.g. `sha256:` of the released
    binary or image). It is distinct from the AdapterManifest digest, which
    covers the manifest content itself.
    """

    name: str
    url: str
    version: str
    digest: str

    def __post_init__(self) -> None:
        if not self.name:
            raise DomainValidationError("AdapterUpstream.name must be non-empty")
        if not self.version:
            raise DomainValidationError("AdapterUpstream.version must be non-empty")


@dataclass(frozen=True, slots=True)
class AdapterManifest:
    """Declarative Adapter manifest (§8.1).

    `digest` is a canonical digest over the manifest content (excluding the
    `digest` field itself) so manifest integrity is verifiable without
    self-reference. It is computed at construction time.
    """

    id: str
    version: str
    adapter_api_version: str
    license: str
    upstream: AdapterUpstream
    risk_class: RiskClass
    coverage_domain: tuple[CoverageDomain, ...]
    input_schema: str
    output_schema: str
    network_policy: str
    parser: str
    fixtures: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    digest: str = field(default="")

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError("AdapterManifest.id must be non-empty")
        if not self.version:
            raise DomainValidationError("AdapterManifest.version must be non-empty")
        if not self.adapter_api_version:
            raise DomainValidationError(
                "AdapterManifest.adapter_api_version must be non-empty"
            )
        if not self.license:
            raise DomainValidationError("AdapterManifest.license must be non-empty")
        if not self.coverage_domain:
            raise DomainValidationError(
                "AdapterManifest.coverage_domain must be non-empty"
            )
        if not self.input_schema:
            raise DomainValidationError(
                "AdapterManifest.input_schema must be non-empty"
            )
        if not self.output_schema:
            raise DomainValidationError(
                "AdapterManifest.output_schema must be non-empty"
            )
        if not self.network_policy:
            raise DomainValidationError(
                "AdapterManifest.network_policy must be non-empty"
            )
        if not self.parser:
            raise DomainValidationError("AdapterManifest.parser must be non-empty")
        # Compute digest over all fields except `digest` itself to avoid
        # self-reference. frozen=True means we must bypass __setattr__.
        payload = {
            f.name: getattr(self, f.name)
            for f in fields(self)
            if f.name != "digest"
        }
        object.__setattr__(self, "digest", canonical_digest(payload))


@dataclass(frozen=True, slots=True)
class ExecutionPolicy:
    """Per-run execution envelope (timeout, concurrency, network profile)."""

    timeout_seconds: int
    max_concurrency: int
    network_profile: str

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise DomainValidationError(
                "ExecutionPolicy.timeout_seconds must be positive"
            )
        if self.max_concurrency <= 0:
            raise DomainValidationError(
                "ExecutionPolicy.max_concurrency must be positive"
            )
        if not self.network_profile:
            raise DomainValidationError(
                "ExecutionPolicy.network_profile must be non-empty"
            )


@dataclass(frozen=True, slots=True)
class AdapterInput:
    """Input contract for an Adapter run.

    `engagement_id` links the run to its parent engagement/assessment (the M0
    domain uses `assessment_id`; the adapter plane keeps the broader term
    `engagement_id` to stay decoupled from assessment lifecycle internals).
    `targets` MUST be non-empty - an Adapter with nothing to scan is a caller
    bug, not a valid execution.
    """

    run_id: str
    engagement_id: str
    scope_snapshot: dict[str, object]
    targets: tuple[str, ...]
    options: dict[str, object]
    execution_policy: ExecutionPolicy

    def __post_init__(self) -> None:
        if not self.run_id:
            raise DomainValidationError("AdapterInput.run_id must be non-empty")
        if not self.engagement_id:
            raise DomainValidationError(
                "AdapterInput.engagement_id must be non-empty"
            )
        if not self.targets:
            raise DomainValidationError("AdapterInput.targets must be non-empty")


@dataclass(frozen=True, slots=True)
class Artifact:
    """Raw output artifact handle (content-addressed, CAS-stored).

    `sha256` is the artifact content digest; `storage_uri` is the CAS URI the
    Adapter wrote the bytes to. Downstream code reads artifacts by digest, not
    by URI, so URI reshuffling never invalidates references.
    """

    id: str
    kind: str
    sha256: str
    storage_uri: str

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError("Artifact.id must be non-empty")
        if not self.kind:
            raise DomainValidationError("Artifact.kind must be non-empty")
        if not self.sha256:
            raise DomainValidationError("Artifact.sha256 must be non-empty")
        if not self.storage_uri:
            raise DomainValidationError("Artifact.storage_uri must be non-empty")


@dataclass(frozen=True, slots=True)
class Observation:
    """Faraday-style unified Observation (§8.3).

    Low-trust, repeatable, source-attributed fact emitted by a tool. The
    `cwe`/`cve`/`owasp` tuples feed CoverageMatrix; `confidence` is a
    probability in [0.0, 1.0]; `severity` and `coverage_domain` are enums so
    downstream correlation and policy never parse free text. `raw` preserves
    the original tool output for audit/replay.
    """

    external_id: str
    asset_identity: str
    source: AdapterSource
    rule_id: str
    rule_version: str
    coverage_domain: CoverageDomain
    title: str
    severity: Severity
    confidence: float
    cwe: tuple[str, ...] = ()
    cve: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    evidence_artifact_ids: tuple[str, ...] = ()
    raw: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.external_id:
            raise DomainValidationError("Observation.external_id must be non-empty")
        if not self.asset_identity:
            raise DomainValidationError(
                "Observation.asset_identity must be non-empty"
            )
        if not self.rule_id:
            raise DomainValidationError("Observation.rule_id must be non-empty")
        if not self.rule_version:
            raise DomainValidationError(
                "Observation.rule_version must be non-empty"
            )
        if not self.title:
            raise DomainValidationError("Observation.title must be non-empty")
        if not _CONFIDENCE_MIN <= self.confidence <= _CONFIDENCE_MAX:
            raise DomainValidationError(
                "Observation.confidence must be in [0.0, 1.0]"
            )


@dataclass(frozen=True, slots=True)
class AdapterOutput:
    """Output contract for an Adapter run.

    `observations` are the normalized §8.3 records that downstream
    CoverageMatrix and Finding correlation consume; `artifacts` are raw output
    handles; `errors` carries parser/runner errors that did not fail the whole
    run (status PARTIAL) or did (status FAILED).
    """

    run_id: str
    status: OutputStatus
    tool: AdapterSource
    artifacts: tuple[Artifact, ...] = ()
    observations: tuple[Observation, ...] = ()
    errors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.run_id:
            raise DomainValidationError("AdapterOutput.run_id must be non-empty")
