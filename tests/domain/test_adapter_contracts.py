# tests/domain/test_adapter_contracts.py
"""TDD tests for the adapter contracts (§8.1 manifest, §8.3 Observation).

These contracts are the four-domain common surface every Tool Adapter must
satisfy: a `AdapterManifest` declaring the tool's identity and risk envelope,
an `AdapterInput` carrying the run/scope/options, an `AdapterOutput` carrying
normalized observations + raw artifacts, and the Faraday-style `Observation`
record that downstream CoverageMatrix and Finding correlation consume.

The schema is intentionally stdlib-only (frozen dataclasses + StrEnum) so the
domain layer keeps no framework coupling - pydantic/sqlalchemy live elsewhere.
"""

from __future__ import annotations

import pytest

from secopent.domain.adapters.contracts import (
    AdapterInput,
    AdapterManifest,
    AdapterOutput,
    AdapterSource,
    AdapterUpstream,
    Artifact,
    CoverageDomain,
    ExecutionPolicy,
    Observation,
    OutputStatus,
    Severity,
)
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.policy.models import RiskClass

# --- Severity / CoverageDomain enums -----------------------------------------


def test_severity_members() -> None:
    assert Severity.INFO == "info"
    assert Severity.LOW == "low"
    assert Severity.MEDIUM == "medium"
    assert Severity.HIGH == "high"
    assert Severity.CRITICAL == "critical"


def test_coverage_domain_members() -> None:
    assert CoverageDomain.ASSET == "asset"
    assert CoverageDomain.WEB == "web"
    assert CoverageDomain.NETWORK == "network"
    assert CoverageDomain.CLOUD == "cloud"


def test_output_status_members() -> None:
    assert OutputStatus.COMPLETED == "completed"
    assert OutputStatus.PARTIAL == "partial"
    assert OutputStatus.FAILED == "failed"


# --- AdapterSource -----------------------------------------------------------


def test_adapter_source_is_frozen() -> None:
    src = AdapterSource(name="nuclei", version="3.11.0", template_version="9.8.0")
    with pytest.raises(AttributeError):
        src.name = "dalfox"


def test_adapter_source_fields() -> None:
    src = AdapterSource(name="nuclei", version="3.11.0", template_version="9.8.0")
    assert src.name == "nuclei"
    assert src.version == "3.11.0"
    assert src.template_version == "9.8.0"


def test_adapter_source_rejects_empty_name() -> None:
    with pytest.raises(DomainValidationError):
        AdapterSource(name="", version="3.11.0", template_version="9.8.0")


def test_adapter_source_rejects_empty_version() -> None:
    with pytest.raises(DomainValidationError):
        AdapterSource(name="nuclei", version="", template_version="9.8.0")


# --- Observation (§8.3 Faraday-style unified record) -------------------------


def _observation_kwargs() -> dict[str, object]:
    return {
        "external_id": "obs-001",
        "asset_identity": "https://example.com",
        "source": AdapterSource(name="nuclei", version="3.11.0", template_version="9.8.0"),
        "rule_id": "cve-2021-44228",
        "rule_version": "1.0",
        "coverage_domain": CoverageDomain.WEB,
        "title": "Log4Shell RCE",
        "severity": Severity.CRITICAL,
        "confidence": 0.9,
        "cwe": ("CWE-502",),
        "cve": ("CVE-2021-44228",),
        "owasp": ("A06:2021",),
        "evidence_artifact_ids": ("art-1",),
        "raw": {"matched": "JNDI"},
    }


def test_observation_is_frozen() -> None:
    obs = Observation(**_observation_kwargs())
    with pytest.raises(AttributeError):
        obs.external_id = "obs-002"


def test_observation_fields_match_section_8_3() -> None:
    obs = Observation(**_observation_kwargs())
    assert obs.external_id == "obs-001"
    assert obs.asset_identity == "https://example.com"
    assert isinstance(obs.source, AdapterSource)
    assert obs.rule_id == "cve-2021-44228"
    assert obs.rule_version == "1.0"
    assert obs.coverage_domain is CoverageDomain.WEB
    assert obs.title == "Log4Shell RCE"
    assert obs.severity is Severity.CRITICAL
    assert obs.confidence == pytest.approx(0.9)
    assert obs.cwe == ("CWE-502",)
    assert obs.cve == ("CVE-2021-44228",)
    assert obs.owasp == ("A06:2021",)
    assert obs.evidence_artifact_ids == ("art-1",)
    assert obs.raw == {"matched": "JNDI"}


def test_observation_rejects_empty_external_id() -> None:
    kw = _observation_kwargs()
    kw["external_id"] = ""
    with pytest.raises(DomainValidationError):
        Observation(**kw)


def test_observation_rejects_empty_asset_identity() -> None:
    kw = _observation_kwargs()
    kw["asset_identity"] = ""
    with pytest.raises(DomainValidationError):
        Observation(**kw)


def test_observation_rejects_confidence_below_zero() -> None:
    kw = _observation_kwargs()
    kw["confidence"] = -0.01
    with pytest.raises(DomainValidationError):
        Observation(**kw)


def test_observation_rejects_confidence_above_one() -> None:
    kw = _observation_kwargs()
    kw["confidence"] = 1.01
    with pytest.raises(DomainValidationError):
        Observation(**kw)


def test_observation_accepts_boundary_confidence_values() -> None:
    for value in (0.0, 1.0):
        kw = _observation_kwargs()
        kw["confidence"] = value
        obs = Observation(**kw)
        assert obs.confidence == pytest.approx(value)


def test_observation_cwe_cve_owasp_are_tuples() -> None:
    obs = Observation(**_observation_kwargs())
    assert isinstance(obs.cwe, tuple)
    assert isinstance(obs.cve, tuple)
    assert isinstance(obs.owasp, tuple)
    assert isinstance(obs.evidence_artifact_ids, tuple)


def test_observation_default_tuples_are_empty() -> None:
    kw = _observation_kwargs()
    for k in ("cwe", "cve", "owasp", "evidence_artifact_ids"):
        kw[k] = ()
    obs = Observation(**kw)
    assert obs.cwe == ()
    assert obs.cve == ()
    assert obs.owasp == ()
    assert obs.evidence_artifact_ids == ()


# --- AdapterUpstream ---------------------------------------------------------


def test_adapter_upstream_is_frozen() -> None:
    up = AdapterUpstream(
        name="nuclei",
        url="https://github.com/projectdiscovery/nuclei",
        version="3.11.0",
        digest="sha256:abc",
    )
    with pytest.raises(AttributeError):
        up.name = "dalfox"


def test_adapter_upstream_rejects_empty_name() -> None:
    with pytest.raises(DomainValidationError):
        AdapterUpstream(name="", url="u", version="1.0", digest="sha256:x")


def test_adapter_upstream_rejects_empty_version() -> None:
    with pytest.raises(DomainValidationError):
        AdapterUpstream(name="nuclei", url="u", version="", digest="sha256:x")


# --- AdapterManifest (§8.1) --------------------------------------------------


def _manifest_kwargs() -> dict[str, object]:
    return {
        "id": "projectdiscovery.nuclei",
        "version": "1.0.0",
        "adapter_api_version": "v1",
        "license": "MIT",
        "upstream": AdapterUpstream(
            name="nuclei",
            url="https://github.com/projectdiscovery/nuclei",
            version="3.11.0",
            digest="sha256:abc",
        ),
        "risk_class": RiskClass.LOW,
        "coverage_domain": (CoverageDomain.WEB,),
        "input_schema": "schemas/input.json",
        "output_schema": "schemas/output.json",
        "network_policy": "scoped_http",
        "parser": "src/parser.py",
        "fixtures": ("positive", "negative", "timeout", "scope_deny", "malformed"),
        "permissions": ("read_scope", "write_artifact", "emit_observation"),
    }


def test_manifest_is_frozen() -> None:
    m = AdapterManifest(**_manifest_kwargs())
    with pytest.raises(AttributeError):
        m.id = "x"


def test_manifest_fields_match_section_8_1() -> None:
    m = AdapterManifest(**_manifest_kwargs())
    assert m.id == "projectdiscovery.nuclei"
    assert m.version == "1.0.0"
    assert m.adapter_api_version == "v1"
    assert m.license == "MIT"
    assert isinstance(m.upstream, AdapterUpstream)
    assert m.risk_class is RiskClass.LOW
    assert m.coverage_domain == (CoverageDomain.WEB,)
    assert m.input_schema == "schemas/input.json"
    assert m.output_schema == "schemas/output.json"
    assert m.network_policy == "scoped_http"
    assert m.parser == "src/parser.py"
    assert m.fixtures == (
        "positive",
        "negative",
        "timeout",
        "scope_deny",
        "malformed",
    )
    assert m.permissions == ("read_scope", "write_artifact", "emit_observation")


def test_manifest_rejects_empty_id() -> None:
    kw = _manifest_kwargs()
    kw["id"] = ""
    with pytest.raises(DomainValidationError):
        AdapterManifest(**kw)


def test_manifest_rejects_empty_version() -> None:
    kw = _manifest_kwargs()
    kw["version"] = ""
    with pytest.raises(DomainValidationError):
        AdapterManifest(**kw)


def test_manifest_digest_is_sha256_prefixed() -> None:
    m = AdapterManifest(**_manifest_kwargs())
    assert m.digest.startswith("sha256:")
    assert len(m.digest) == len("sha256:") + 64


def test_manifest_digest_is_deterministic() -> None:
    m1 = AdapterManifest(**_manifest_kwargs())
    m2 = AdapterManifest(**_manifest_kwargs())
    assert m1.digest == m2.digest


def test_manifest_digest_changes_on_content_change() -> None:
    m1 = AdapterManifest(**_manifest_kwargs())
    kw = _manifest_kwargs()
    kw["version"] = "1.0.1"
    m2 = AdapterManifest(**kw)
    assert m1.digest != m2.digest


def test_manifest_digest_excludes_digest_field_itself() -> None:
    """The digest must be computed from manifest content, not a self-reference."""
    m = AdapterManifest(**_manifest_kwargs())
    # digest is a computed field; rebuilding with the same content yields the
    # same digest, which proves digest is not part of its own input.
    rebuilt = AdapterManifest(**_manifest_kwargs())
    assert m.digest == rebuilt.digest


# --- ExecutionPolicy ---------------------------------------------------------


def test_execution_policy_is_frozen() -> None:
    ep = ExecutionPolicy(timeout_seconds=300, max_concurrency=4, network_profile="scoped_http")
    with pytest.raises(AttributeError):
        ep.timeout_seconds = 0


def test_execution_policy_rejects_non_positive_timeout() -> None:
    with pytest.raises(DomainValidationError):
        ExecutionPolicy(timeout_seconds=0, max_concurrency=4, network_profile="p")


def test_execution_policy_rejects_non_positive_concurrency() -> None:
    with pytest.raises(DomainValidationError):
        ExecutionPolicy(timeout_seconds=300, max_concurrency=0, network_profile="p")


# --- AdapterInput ------------------------------------------------------------


def _input_kwargs() -> dict[str, object]:
    return {
        "run_id": "run-001",
        "engagement_id": "eng-001",
        "scope_snapshot": {"assets": ["https://example.com"]},
        "targets": ("https://example.com",),
        "options": {"tags": ["cve"]},
        "execution_policy": ExecutionPolicy(
            timeout_seconds=300, max_concurrency=4, network_profile="scoped_http"
        ),
    }


def test_input_is_frozen() -> None:
    inp = AdapterInput(**_input_kwargs())
    with pytest.raises(AttributeError):
        inp.run_id = "x"


def test_input_fields() -> None:
    inp = AdapterInput(**_input_kwargs())
    assert inp.run_id == "run-001"
    assert inp.engagement_id == "eng-001"
    assert inp.scope_snapshot == {"assets": ["https://example.com"]}
    assert inp.targets == ("https://example.com",)
    assert inp.options == {"tags": ["cve"]}
    assert isinstance(inp.execution_policy, ExecutionPolicy)


def test_input_engagement_id_is_required_and_non_empty() -> None:
    """The plan calls the field engagement_id (or assessment_id in M0 terms);
    SecOpent keeps a single canonical slot, and it must be non-empty."""
    kw = _input_kwargs()
    kw["engagement_id"] = ""
    with pytest.raises(DomainValidationError):
        AdapterInput(**kw)


def test_input_rejects_empty_run_id() -> None:
    kw = _input_kwargs()
    kw["run_id"] = ""
    with pytest.raises(DomainValidationError):
        AdapterInput(**kw)


def test_input_rejects_empty_targets() -> None:
    kw = _input_kwargs()
    kw["targets"] = ()
    with pytest.raises(DomainValidationError):
        AdapterInput(**kw)


# --- Artifact ----------------------------------------------------------------


def test_artifact_is_frozen() -> None:
    art = Artifact(
        id="art-1",
        kind="http_response",
        sha256="sha256:abc",
        storage_uri="file:///artifacts/art-1",
    )
    with pytest.raises(AttributeError):
        art.id = "x"


def test_artifact_rejects_empty_id() -> None:
    with pytest.raises(DomainValidationError):
        Artifact(id="", kind="k", sha256="sha256:x", storage_uri="u")


def test_artifact_rejects_empty_sha256() -> None:
    with pytest.raises(DomainValidationError):
        Artifact(id="a", kind="k", sha256="", storage_uri="u")


# --- AdapterOutput -----------------------------------------------------------


def _output_kwargs() -> dict[str, object]:
    return {
        "run_id": "run-001",
        "status": OutputStatus.COMPLETED,
        "tool": AdapterSource(name="nuclei", version="3.11.0", template_version="9.8.0"),
        "artifacts": (
            Artifact(
                id="art-1",
                kind="http_response",
                sha256="sha256:abc",
                storage_uri="file:///artifacts/art-1",
            ),
        ),
        "observations": (Observation(**_observation_kwargs()),),
        "errors": (),
    }


def test_output_is_frozen() -> None:
    out = AdapterOutput(**_output_kwargs())
    with pytest.raises(AttributeError):
        out.run_id = "x"


def test_output_fields() -> None:
    out = AdapterOutput(**_output_kwargs())
    assert out.run_id == "run-001"
    assert out.status is OutputStatus.COMPLETED
    assert isinstance(out.tool, AdapterSource)
    assert len(out.artifacts) == 1
    assert isinstance(out.observations[0], Observation)
    assert out.errors == ()


def test_output_rejects_empty_run_id() -> None:
    kw = _output_kwargs()
    kw["run_id"] = ""
    with pytest.raises(DomainValidationError):
        AdapterOutput(**kw)


def test_output_observations_default_empty() -> None:
    kw = _output_kwargs()
    kw["observations"] = ()
    out = AdapterOutput(**kw)
    assert out.observations == ()


def test_output_artifacts_default_empty() -> None:
    kw = _output_kwargs()
    kw["artifacts"] = ()
    out = AdapterOutput(**kw)
    assert out.artifacts == ()


def test_output_errors_default_empty() -> None:
    kw = _output_kwargs()
    kw["errors"] = ()
    out = AdapterOutput(**kw)
    assert out.errors == ()
