# tests/domain/test_peer_agents.py
"""Domain tests for peer agent models (integration spec §5 P0)."""
from __future__ import annotations

import pytest

from secopent.domain.adapters.contracts import CoverageDomain, Severity
from secopent.domain.catalog.models import AssetType, RequiredTestClass, TestCatalog
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.peer_agents.models import (
    PeerAgentBudget,
    PeerAgentDescriptor,
    PeerAgentFinding,
    PeerAgentReport,
    PeerAgentRun,
    PeerAgentTrustLevel,
    PeerRunStatus,
    RejectionReason,
)
from secopent.domain.peer_agents.normalize import (
    finding_in_scope,
    hits_required_catalog,
    normalize_finding,
)
from secopent.domain.peer_agents.registry import (
    PeerAgentAlreadyRegistered,
    PeerAgentRegistry,
    default_registry,
)
from secopent.domain.scope.models import ScopeSnapshot


def _budget() -> PeerAgentBudget:
    return PeerAgentBudget(max_wall_seconds=1800, max_cost_units=100.0)


def _descriptor() -> PeerAgentDescriptor:
    return PeerAgentDescriptor(
        name="strix",
        version="1.4.1",
        license="Apache-2.0",
        trust_level=PeerAgentTrustLevel.ADOPTED_EXTERNAL,
        capabilities=("web", "api"),
        cost_class="llm_tokens",
        default_budget=_budget(),
    )


class TestPeerAgentBudget:
    def test_rejects_negative_wall_seconds(self) -> None:
        with pytest.raises(DomainValidationError):
            PeerAgentBudget(max_wall_seconds=-1, max_cost_units=10.0)

    def test_rejects_negative_cost_units(self) -> None:
        with pytest.raises(DomainValidationError):
            PeerAgentBudget(max_wall_seconds=60, max_cost_units=-0.1)

    def test_accepts_zero_budget(self) -> None:
        budget = PeerAgentBudget(max_wall_seconds=0, max_cost_units=0.0)
        assert budget.max_wall_seconds == 0


class TestPeerAgentDescriptor:
    def test_rejects_empty_name(self) -> None:
        with pytest.raises(DomainValidationError):
            PeerAgentDescriptor(
                name="", version="1.0", license="MIT",
                trust_level=PeerAgentTrustLevel.UNTRUSTED,
                capabilities=(), cost_class="llm_tokens",
                default_budget=_budget(),
            )

    def test_is_frozen(self) -> None:
        descriptor = _descriptor()
        with pytest.raises(AttributeError):
            descriptor.name = "other"  # type: ignore[misc]


class TestPeerAgentRun:
    def test_defaults_to_pending_with_no_timestamps(self) -> None:
        run = PeerAgentRun(
            id="run-1", agent_name="strix", agent_version="1.4.1",
            assessment_id="asmt-1", targets=("http://host.docker.internal:3000",),
            budget=_budget(), permit_id="permit-1",
        )
        assert run.status is PeerRunStatus.PENDING
        assert run.started_at is None and run.finished_at is None

    def test_rejects_empty_targets(self) -> None:
        with pytest.raises(DomainValidationError):
            PeerAgentRun(
                id="run-1", agent_name="strix", agent_version="1.4.1",
                assessment_id="asmt-1", targets=(), budget=_budget(),
                permit_id="permit-1",
            )


class TestPeerAgentFinding:
    def test_requires_provenance_fields(self) -> None:
        with pytest.raises(DomainValidationError):
            PeerAgentFinding(
                id="f-1", run_id="", agent_name="strix", title="SQLi",
                asset="http://t", severity_hint="high",
            )

    def test_defaults_empty_hint_tuples(self) -> None:
        finding = PeerAgentFinding(
            id="f-1", run_id="run-1", agent_name="strix",
            title="SQLi in /login", asset="http://host.docker.internal:3000",
            severity_hint="high",
        )
        assert finding.cwe == () and finding.owasp == () and finding.cve == ()


class TestPeerAgentReport:
    def test_holds_findings_and_costs(self) -> None:
        finding = PeerAgentFinding(
            id="f-1", run_id="run-1", agent_name="strix",
            title="t", asset="http://t", severity_hint="low",
        )
        report = PeerAgentReport(
            run_id="run-1", findings=(finding,),
            wall_seconds=120.5, cost_units=3.2, exit_code=0,
        )
        assert len(report.findings) == 1


class TestEnums:
    def test_trust_levels(self) -> None:
        assert PeerAgentTrustLevel.ADOPTED_EXTERNAL.value == "adopted_external_agent"
        assert PeerAgentTrustLevel.UNTRUSTED.value == "untrusted"

    def test_rejection_reasons_cover_spec_gates(self) -> None:
        # spec §4: 目录外噪音拒收 + scope 越界拒收 + 解析失败
        assert {r.value for r in RejectionReason} == {
            "out_of_scope", "out_of_catalog", "parse_error",
        }


class TestPeerAgentRegistry:
    def test_default_registry_is_empty(self) -> None:
        assert default_registry().all() == ()

    def test_register_then_get(self) -> None:
        registry = PeerAgentRegistry()
        descriptor = _descriptor()
        registry.register(descriptor)
        assert registry.get("strix") == descriptor

    def test_get_unknown_returns_none(self) -> None:
        assert PeerAgentRegistry().get("nope") is None

    def test_duplicate_registration_rejected(self) -> None:
        registry = PeerAgentRegistry()
        registry.register(_descriptor())
        with pytest.raises(PeerAgentAlreadyRegistered):
            registry.register(_descriptor())

    def test_all_returns_registered_descriptors(self) -> None:
        registry = PeerAgentRegistry()
        registry.register(_descriptor())
        assert len(registry.all()) == 1


def _scope() -> ScopeSnapshot:
    """构造方式与 tests/domain/test_scope.py::_snapshot 同款。"""
    from datetime import UTC, datetime

    from secopent.domain.scope.models import ScopeLimits

    return ScopeSnapshot(
        id="snap",
        project_id="proj",
        include=("host.docker.internal", "http://host.docker.internal:3000"),
        exclude=(),
        ports=(3000,),
        limits=ScopeLimits(requests_per_second=5.0, concurrency=3, max_requests=1000),
        approved_by="analyst",
        approved_at=datetime(2026, 1, 1, tzinfo=UTC),
        digest="sha256:" + "0" * 64,
    )


def _catalog() -> TestCatalog:
    from secopent.domain.policy.models import RiskClass

    return TestCatalog(
        version="test-1",
        mappings={
            AssetType.WEB_APP: (
                RequiredTestClass(
                    id="sql-injection",
                    cwe=("CWE-89",),
                    owasp=("WSTG-INPV-05",),
                    risk=RiskClass.ACTIVE,
                ),
            ),
        },
    )


def _finding(**overrides: object) -> PeerAgentFinding:
    base: dict[str, object] = dict(
        id="f-1", run_id="run-1", agent_name="strix",
        title="SQLi in /login",
        asset="http://host.docker.internal:3000",
        severity_hint="high", cwe=("CWE-89",), owasp=("WSTG-INPV-05",),
    )
    base.update(overrides)
    return PeerAgentFinding(**base)  # type: ignore[arg-type]


class TestScopeGate:
    def test_url_asset_in_scope(self) -> None:
        assert finding_in_scope(_finding(), _scope()) is True

    def test_foreign_asset_out_of_scope(self) -> None:
        foreign = _finding(asset="http://evil.example.com")
        assert finding_in_scope(foreign, _scope()) is False

    def test_bare_hostname_checked_as_domain(self) -> None:
        bare = _finding(asset="host.docker.internal")
        assert finding_in_scope(bare, _scope()) is True


class TestCatalogGate:
    def test_finding_with_matching_cwe_hits_catalog(self) -> None:
        assert hits_required_catalog(_finding(), _catalog(), AssetType.WEB_APP) is True

    def test_finding_without_matching_class_misses_catalog(self) -> None:
        off = _finding(cwe=("CWE-79",), owasp=())
        assert hits_required_catalog(off, _catalog(), AssetType.WEB_APP) is False


class TestNormalizeFinding:
    def test_maps_to_observation_with_peer_source(self) -> None:
        run = PeerAgentRun(
            id="run-1", agent_name="strix", agent_version="1.4.1",
            assessment_id="asmt-1",
            targets=("http://host.docker.internal:3000",),
            budget=_budget(), permit_id="permit-1",
        )
        observation = normalize_finding(_finding(), run)
        assert observation.source.name == "peer:strix"
        assert observation.source.version == "1.4.1"
        assert observation.external_id == "f-1"
        assert observation.coverage_domain is CoverageDomain.WEB
        assert observation.confidence == 0.5
        assert observation.raw["peer_run_id"] == "run-1"

    def test_known_severity_hint_maps_to_enum(self) -> None:
        run = PeerAgentRun(
            id="run-1", agent_name="strix", agent_version="1.4.1",
            assessment_id="asmt-1", targets=("http://t",),
            budget=_budget(), permit_id="p",
        )
        observation = normalize_finding(_finding(severity_hint="CRITICAL"), run)
        assert observation.severity is Severity.CRITICAL

    def test_unknown_severity_hint_downgrades_to_info_and_records(self) -> None:
        run = PeerAgentRun(
            id="run-1", agent_name="strix", agent_version="1.4.1",
            assessment_id="asmt-1", targets=("http://t",),
            budget=_budget(), permit_id="p",
        )
        observation = normalize_finding(
            _finding(severity_hint="apocalyptic"), run
        )
        assert observation.severity is Severity.INFO
        assert observation.raw["severity_hint_unmapped"] == "apocalyptic"
