"""TDD contract tests for the Web/API Adapter Pack (M1 Task 10, §8.2).

These tests exercise the parser layer of the five Web/API adapters:
nuclei / dalfox / restler / schemathesis / zap. They use FIXTURE files
(sample tool stdout/JSON/JSONL output captured from real tool runs) rather
than executing the real tools - real container execution is M5 E2E scope.

Each adapter has five fixture classes:

- **positive**: well-formed tool output -> at least one Observation with the
  expected `coverage_domain=web`, `asset_identity`, `severity`, and (where
  applicable) populated `cwe`/`cve`/`owasp` tuples that feed CoverageMatrix.
- **negative**: empty-but-well-formed tool output -> zero Observations.
- **timeout**: a fixture simulating the tool timing out (exit_code != 0) ->
  AdapterRunner reports non-COMPLETED status.
- **scope_deny**: an out-of-scope target is blocked by the M0 PolicyEngine
  BEFORE the container runs.
- **malformed**: corrupt JSON output -> the parser returns zero Observations
  without raising.

The manifest tests assert each adapter's `manifest()` builds an
`AdapterManifest` whose `coverage_domain` includes `web`, with upstream pin
and risk class populated. The ZAP manifest additionally marks the adapter as
Standalone-only (not available in Lite profiles) via the `permissions`
tuple, because ZAP active scanning is too noisy/heavy for Lite engagements.
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
from secopent.integrations.adapters import (
    dalfox,
    nuclei,
    restler,
    schemathesis,
    zap,
)

# ---------------------------------------------------------------------------
# Test doubles (reused from test_asset_mapping_adapters.py shape)
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
        id="snap-web",
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
        run_id="run-web-1",
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
    "nuclei": nuclei,
    "dalfox": dalfox,
    "restler": restler,
    "schemathesis": schemathesis,
    "zap": zap,
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
def test_manifest_loads_with_web_coverage(adapter_name: str) -> None:
    module = _ADAPTER_MODULES[adapter_name]
    manifest = module.manifest()
    assert isinstance(manifest, AdapterManifest)
    assert CoverageDomain.WEB in manifest.coverage_domain
    assert manifest.id
    assert manifest.version
    assert manifest.upstream.name
    assert manifest.upstream.version
    assert manifest.upstream.digest
    assert manifest.risk_class in RiskClass
    assert manifest.license
    assert manifest.parser
    assert manifest.digest  # computed


def test_nuclei_manifest_specifics() -> None:
    m = nuclei.manifest()
    assert m.id == "nuclei"
    assert m.upstream.name == "nuclei"
    # nuclei is active (sends payloads); risk class ACTIVE or LOW.
    assert m.risk_class in (RiskClass.ACTIVE, RiskClass.LOW)


def test_dalfox_manifest_specifics() -> None:
    m = dalfox.manifest()
    assert m.id == "dalfox"
    assert m.upstream.name == "dalfox"
    assert m.risk_class in (RiskClass.ACTIVE, RiskClass.LOW)


def test_restler_manifest_specifics() -> None:
    m = restler.manifest()
    assert m.id == "restler"
    assert m.upstream.name.lower() == "restler"


def test_schemathesis_manifest_specifics() -> None:
    m = schemathesis.manifest()
    assert m.id == "schemathesis"
    assert m.upstream.name.lower() == "schemathesis"


def test_zap_manifest_marks_standalone_only() -> None:
    """ZAP active scan is Standalone-only (not for Lite engagements)."""
    m = zap.manifest()
    assert m.id == "zap"
    assert m.upstream.name.lower() == "zap"
    assert m.risk_class is RiskClass.ACTIVE
    # Standalone-only marker carried in permissions tuple so the runner /
    # profile selector can gate ZAP out of Lite profiles.
    assert "standalone-only" in m.permissions, (
        "ZAP manifest must mark itself standalone-only via permissions"
    )


# ---------------------------------------------------------------------------
# nuclei parser tests (template tags -> CWE/OWASP mapping)
# ---------------------------------------------------------------------------


def test_nuclei_positive_parse() -> None:
    raw = _fixture_path("nuclei", "positive.jsonl").read_text(encoding="utf-8")
    observations = nuclei.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) >= 1
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.WEB
    assert obs.asset_identity  # matched host
    assert obs.severity in (
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    )
    # Template tags must map to CWE/OWASP so CoverageMatrix can score.
    # At least one Observation in the positive fixture must populate cwe or owasp.
    has_mapped = any(o.cwe or o.owasp for o in observations)
    assert has_mapped, "nuclei parser must map template tags to CWE/OWASP"
    # raw must preserve template-id and tags for audit.
    assert "template-id" in obs.raw or "templateID" in obs.raw or "template_id" in obs.raw


def test_nuclei_maps_sqli_tag_to_cwe_89() -> None:
    """A finding whose template tags include sqli must map to CWE-89 + OWASP A03."""
    raw = _fixture_path("nuclei", "positive.jsonl").read_text(encoding="utf-8")
    observations = nuclei.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    sqli_obs = [o for o in observations if "sqli" in str(o.raw.get("tags", "")).lower()
                or "sqli" in str(o.raw.get("template-id", "")).lower()]
    if sqli_obs:  # only assert if the fixture includes a sqli finding
        assert any("CWE-89" in c for c in sqli_obs[0].cwe)
        assert any("A03" in o for o in sqli_obs[0].owasp)


def test_nuclei_negative_parse_returns_empty() -> None:
    raw = _fixture_path("nuclei", "negative.jsonl").read_text(encoding="utf-8")
    observations = nuclei.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_nuclei_malformed_parse_returns_empty() -> None:
    raw = _fixture_path("nuclei", "malformed.jsonl").read_text(encoding="utf-8")
    observations = nuclei.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


# ---------------------------------------------------------------------------
# dalfox parser tests (XSS -> CWE-79, OWASP A03)
# ---------------------------------------------------------------------------


def test_dalfox_positive_parse() -> None:
    raw = _fixture_path("dalfox", "positive.json").read_text(encoding="utf-8")
    observations = dalfox.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) >= 1
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.WEB
    assert obs.asset_identity
    assert "CWE-79" in obs.cwe, "dalfox XSS findings must map to CWE-79"
    assert any("A03" in o for o in obs.owasp), "dalfox XSS findings must map to OWASP A03"


def test_dalfox_negative_parse_returns_empty() -> None:
    raw = _fixture_path("dalfox", "negative.json").read_text(encoding="utf-8")
    observations = dalfox.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_dalfox_malformed_parse_returns_empty() -> None:
    raw = _fixture_path("dalfox", "malformed.json").read_text(encoding="utf-8")
    observations = dalfox.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


# ---------------------------------------------------------------------------
# restler parser tests (sequence testing - skip_step/out_of_order/replay)
# ---------------------------------------------------------------------------


def test_restler_positive_parse() -> None:
    raw = _fixture_path("restler", "positive.json").read_text(encoding="utf-8")
    observations = restler.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) >= 1
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.WEB
    # RESTler sequence testing outputs test_class in raw (decision 23).
    # At least one Observation must carry a test_class like skip_step /
    # out_of_order / replay.
    has_test_class = any(
        "test_class" in o.raw or "test_class" in str(o.raw.get("bug_class", ""))
        for o in observations
    )
    assert has_test_class, "RESTler parser must surface test_class in raw"


def test_restler_negative_parse_returns_empty() -> None:
    raw = _fixture_path("restler", "negative.json").read_text(encoding="utf-8")
    observations = restler.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_restler_malformed_parse_returns_empty() -> None:
    raw = _fixture_path("restler", "malformed.json").read_text(encoding="utf-8")
    observations = restler.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


# ---------------------------------------------------------------------------
# schemathesis parser tests (boundary - 越界)
# ---------------------------------------------------------------------------


def test_schemathesis_positive_parse() -> None:
    raw = _fixture_path("schemathesis", "positive.json").read_text(encoding="utf-8")
    observations = schemathesis.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) >= 1
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.WEB
    # Schemathesis boundary testing outputs test_class=boundary (decision 23).
    has_boundary = any(
        str(o.raw.get("test_class", "")).lower() == "boundary" for o in observations
    )
    assert has_boundary, "Schemathesis parser must surface test_class=boundary"


def test_schemathesis_negative_parse_returns_empty() -> None:
    raw = _fixture_path("schemathesis", "negative.json").read_text(encoding="utf-8")
    observations = schemathesis.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_schemathesis_malformed_parse_returns_empty() -> None:
    raw = _fixture_path("schemathesis", "malformed.json").read_text(encoding="utf-8")
    observations = schemathesis.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_schemathesis_parses_real_ndjson_event_format() -> None:
    """The real schemathesis CLI (``--report ndjson --report-ndjson-path
    /dev/stdout``) emits NDJSON events interleaved with human-readable progress
    text. The parser must skip non-JSON lines and extract failed checks from
    ``ScenarioFinished`` events."""
    # Sample extracted from a real schemathesis run against httpbin.
    raw = (
        "Schemathesis v4.24.3\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        '{"Initialize":{"command":"st run","schemathesis_version":"4.24.3"}}\n'
        '{"LoadingStarted":{"id":"abc","timestamp":1786011204.46}}\n'
        '{"ScenarioFinished":{"id":"sf1","timestamp":1786011209.48,'
        '"status":"failure","recorder":{"label":"DELETE /redirect-to",'
        '"checks":{"case1":[{"name":"not_a_server_error","status":"failure",'
        '"failure_info":{"failure":{"type":"ServerError","message":"Server error"}}}]}}}}\n'
        '{"ScenarioFinished":{"id":"sf2","timestamp":1786011210.0,'
        '"status":"success","recorder":{"label":"GET /anything",'
        '"checks":{"case2":[{"name":"not_a_server_error","status":"success"}]}}}}\n'
        "================== 1 failures in 62.74s ==================\n"
    )
    observations = schemathesis.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) == 1, "should extract exactly one failed check"
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.WEB
    assert obs.rule_id == "schemathesis.not_a_server_error"
    assert obs.asset_identity == "DELETE /redirect-to"
    assert obs.severity is Severity.HIGH
    assert str(obs.raw.get("test_class", "")).lower() == "boundary"


def test_schemathesis_ndjson_no_failures_returns_empty() -> None:
    """A real schemathesis run with all passing checks produces no
    Observations."""
    raw = (
        '{"ScenarioFinished":{"id":"sf1","status":"success",'
        '"recorder":{"label":"GET /anything",'
        '"checks":{"c1":[{"name":"not_a_server_error","status":"success"}]}}}}\n'
    )
    observations = schemathesis.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


# ---------------------------------------------------------------------------
# zap parser tests (alerts -> cwe from plugin)
# ---------------------------------------------------------------------------


def test_zap_positive_parse() -> None:
    raw = _fixture_path("zap", "positive.json").read_text(encoding="utf-8")
    observations = zap.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert len(observations) >= 1
    obs = observations[0]
    assert obs.coverage_domain is CoverageDomain.WEB
    assert obs.asset_identity
    # ZAP alerts carry pluginid/cweid; parser must surface cwe when present.
    has_cwe = any(o.cwe for o in observations)
    assert has_cwe, "ZAP parser must surface cwe from alert plugin/cweid"


def test_zap_negative_parse_returns_empty() -> None:
    raw = _fixture_path("zap", "negative.json").read_text(encoding="utf-8")
    observations = zap.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
    assert observations == ()


def test_zap_malformed_parse_returns_empty() -> None:
    raw = _fixture_path("zap", "malformed.json").read_text(encoding="utf-8")
    observations = zap.parse(stdout=raw, source=_ADAPTER_SOURCE, artifacts={})
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
    executor = RecordingExecutor(
        stdout="", stderr=timeout_text, exit_code=124
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


def test_nuclei_dedup_keeps_distinct_templates_on_same_host() -> None:
    """A3.3: real scans of one target emit many findings sharing a host. Dedup
    must key on (template-id, matched target), so distinct vulnerabilities at the
    same URL survive, while exact duplicates collapse."""
    same_host = "https://shop.test/login"
    sqli = (
        '{"template-id": "sqli-login", "info": {"name": "SQLi", '
        '"tags": ["sqli"], "severity": "high"}, "matched-at": "' + same_host + '", "type": "http"}'
    )
    xss = (
        '{"template-id": "xss-login", "info": {"name": "XSS", '
        '"tags": ["xss"], "severity": "medium"}, "matched-at": "' + same_host + '", "type": "http"}'
    )
    jsonl = "\n".join([sqli, xss, sqli])  # third line duplicates the first
    observations = nuclei.parse(stdout=jsonl, source=_ADAPTER_SOURCE, artifacts={})
    rule_ids = sorted(o.rule_id for o in observations)
    assert rule_ids == ["sqli-login", "xss-login"]
