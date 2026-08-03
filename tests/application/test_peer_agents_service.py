# tests/application/test_peer_agents_service.py
"""Application tests for PeerAgentService (integration spec §5 P0)."""
from __future__ import annotations

import pytest

from secopent.application.audit import AuditService
from secopent.application.peer_agents import (
    PeerAgentService,
    PeerRunOutcome,
)
from secopent.application.ports.peer_runs import InMemoryPeerRunRepository
from secopent.domain.catalog.models import AssetType, RequiredTestClass, TestCatalog
from secopent.domain.peer_agents.models import (
    PeerAgentBudget,
    PeerAgentDescriptor,
    PeerAgentFinding,
    PeerAgentNotRegistered,
    PeerAgentReport,
    PeerAgentRun,
    PeerAgentTrustDenied,
    PeerAgentTrustLevel,
    PeerRunScopeViolation,
    PeerRunStatus,
)
from secopent.domain.peer_agents.registry import PeerAgentRegistry
from secopent.domain.policy.models import RiskClass
from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot


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


def _scope() -> ScopeSnapshot:
    """Same construction pattern as tests/domain/test_peer_agents.py."""
    from datetime import UTC, datetime

    return ScopeSnapshot(
        id="snap",
        project_id="proj",
        include=("host.docker.internal", "http://host.docker.internal:3000"),
        exclude=(),
        ports=(3000,),
        limits=ScopeLimits(
            requests_per_second=5.0, concurrency=3, max_requests=1000
        ),
        approved_by="analyst",
        approved_at=datetime(2026, 1, 1, tzinfo=UTC),
        digest="sha256:" + "0" * 64,
    )


def _catalog() -> TestCatalog:
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


class FakeHarness:
    """Records execute/terminate calls; returns a canned report."""

    def __init__(self, report: PeerAgentReport) -> None:
        self.report = report
        self.executed: list[str] = []
        self.terminated: list[str] = []

    def execute(self, run: PeerAgentRun, descriptor: PeerAgentDescriptor) -> PeerAgentReport:
        self.executed.append(run.id)
        return self.report

    def terminate(self, run_id: str) -> bool:
        self.terminated.append(run_id)
        return True


def _in_memory_audit_repo() -> object:
    """Reuse the MemoryAuditRepo pattern from tests/application/conftest.py."""
    from dataclasses import dataclass, field

    from secopent.domain.audit.models import GENESIS_HASH, AuditEvent

    @dataclass
    class _MemoryAuditRepo:
        events: list[AuditEvent] = field(default_factory=list)

        def add(self, e: AuditEvent) -> None:
            self.events.append(e)

        def list_events(self) -> list[AuditEvent]:
            return list(self.events)

        def last_hash(self) -> str:
            return (
                self.events[-1].event_hash.removeprefix("sha256:")
                if self.events
                else GENESIS_HASH
            )

    return _MemoryAuditRepo()


def _service(harness: FakeHarness) -> PeerAgentService:
    registry = PeerAgentRegistry()
    registry.register(_descriptor())
    audit = AuditService(repo=_in_memory_audit_repo())
    return PeerAgentService(
        registry=registry,
        harness=harness,
        audit=audit,
        runs=InMemoryPeerRunRepository(),
    )


def _report_with_sqli() -> PeerAgentReport:
    finding = PeerAgentFinding(
        id="f-1",
        run_id="run-1",
        agent_name="strix",
        title="SQLi in /login",
        asset="http://host.docker.internal:3000",
        severity_hint="high",
        cwe=("CWE-89",),
        owasp=("WSTG-INPV-05",),
    )
    return PeerAgentReport(
        run_id="run-1",
        findings=(finding,),
        wall_seconds=60.0,
        cost_units=2.0,
        exit_code=0,
    )


class TestInMemoryPeerRunRepository:
    def test_add_get_save_roundtrip(self) -> None:
        repo = InMemoryPeerRunRepository()
        run = PeerAgentRun(
            id="run-1",
            agent_name="strix",
            agent_version="1.4.1",
            assessment_id="asmt-1",
            targets=("http://t",),
            budget=PeerAgentBudget(max_wall_seconds=60, max_cost_units=1.0),
            permit_id="p-1",
        )
        repo.add(run)
        assert repo.get("run-1") == run
        updated = PeerAgentRun(
            id=run.id,
            agent_name=run.agent_name,
            agent_version=run.agent_version,
            assessment_id=run.assessment_id,
            targets=run.targets,
            budget=run.budget,
            permit_id=run.permit_id,
            status=PeerRunStatus.COMPLETED,
        )
        repo.save(updated)
        assert repo.get("run-1").status is PeerRunStatus.COMPLETED


class TestLaunchHappyPath:
    def test_launch_produces_normalized_observation(self) -> None:
        service = _service(FakeHarness(_report_with_sqli()))
        outcome = service.launch(
            assessment_id="asmt-1",
            agent_name="strix",
            targets=("http://host.docker.internal:3000",),
            scope=_scope(),
            catalog=_catalog(),
            asset_type=AssetType.WEB_APP,
            actor="operator",
            permit_id="permit-1",
        )
        assert isinstance(outcome, PeerRunOutcome)
        assert outcome.run.status is PeerRunStatus.COMPLETED
        assert len(outcome.observations) == 1
        assert outcome.observations[0].source.name == "peer:strix"
        assert outcome.rejected == ()

    def test_launch_persists_run_and_audits(self) -> None:
        harness = FakeHarness(_report_with_sqli())
        service = _service(harness)
        outcome = service.launch(
            assessment_id="asmt-1",
            agent_name="strix",
            targets=("http://host.docker.internal:3000",),
            scope=_scope(),
            catalog=_catalog(),
            asset_type=AssetType.WEB_APP,
            actor="operator",
            permit_id="permit-1",
        )
        assert service._runs.get(outcome.run.id) is not None  # noqa: SLF001
        assert harness.executed == [outcome.run.id]


class TestLaunchDenials:
    def test_unregistered_agent_rejected(self) -> None:
        service = _service(FakeHarness(_report_with_sqli()))
        with pytest.raises(PeerAgentNotRegistered):
            service.launch(
                assessment_id="asmt-1",
                agent_name="unknown-agent",
                targets=("http://host.docker.internal:3000",),
                scope=_scope(),
                catalog=_catalog(),
                asset_type=AssetType.WEB_APP,
                actor="op",
                permit_id="p",
            )

    def test_untrusted_agent_rejected(self) -> None:
        registry = PeerAgentRegistry()
        registry.register(
            PeerAgentDescriptor(
                name="sketchy",
                version="0.1",
                license="unknown",
                trust_level=PeerAgentTrustLevel.UNTRUSTED,
                capabilities=(),
                cost_class="llm_tokens",
                default_budget=PeerAgentBudget(
                    max_wall_seconds=60, max_cost_units=1
                ),
            )
        )
        service = PeerAgentService(
            registry=registry,
            harness=FakeHarness(_report_with_sqli()),
            audit=AuditService(repo=_in_memory_audit_repo()),
            runs=InMemoryPeerRunRepository(),
        )
        with pytest.raises(PeerAgentTrustDenied):
            service.launch(
                assessment_id="asmt-1",
                agent_name="sketchy",
                targets=("http://host.docker.internal:3000",),
                scope=_scope(),
                catalog=_catalog(),
                asset_type=AssetType.WEB_APP,
                actor="op",
                permit_id="p",
            )

    def test_out_of_scope_launch_target_rejected(self) -> None:
        service = _service(FakeHarness(_report_with_sqli()))
        with pytest.raises(PeerRunScopeViolation):
            service.launch(
                assessment_id="asmt-1",
                agent_name="strix",
                targets=("http://evil.example.com",),
                scope=_scope(),
                catalog=_catalog(),
                asset_type=AssetType.WEB_APP,
                actor="op",
                permit_id="p",
            )


class TestFindingGates:
    def test_out_of_scope_finding_rejected_not_normalized(self) -> None:
        foreign = PeerAgentReport(
            run_id="run-1",
            findings=(
                PeerAgentFinding(
                    id="f-9",
                    run_id="run-1",
                    agent_name="strix",
                    title="SQLi",
                    asset="http://evil.example.com",
                    severity_hint="high",
                    cwe=("CWE-89",),
                ),
            ),
            wall_seconds=1.0,
            cost_units=0.1,
            exit_code=0,
        )
        outcome = _service(FakeHarness(foreign)).launch(
            assessment_id="asmt-1",
            agent_name="strix",
            targets=("http://host.docker.internal:3000",),
            scope=_scope(),
            catalog=_catalog(),
            asset_type=AssetType.WEB_APP,
            actor="op",
            permit_id="p",
        )
        assert outcome.observations == ()
        assert len(outcome.rejected) == 1
        assert outcome.rejected[0].reason.value == "out_of_scope"

    def test_off_catalog_finding_rejected(self) -> None:
        noise = PeerAgentReport(
            run_id="run-1",
            findings=(
                PeerAgentFinding(
                    id="f-8",
                    run_id="run-1",
                    agent_name="strix",
                    title="info leak",
                    asset="http://host.docker.internal:3000",
                    severity_hint="info",
                    cwe=("CWE-200",),
                    owasp=(),
                ),
            ),
            wall_seconds=1.0,
            cost_units=0.1,
            exit_code=0,
        )
        outcome = _service(FakeHarness(noise)).launch(
            assessment_id="asmt-1",
            agent_name="strix",
            targets=("http://host.docker.internal:3000",),
            scope=_scope(),
            catalog=_catalog(),
            asset_type=AssetType.WEB_APP,
            actor="op",
            permit_id="p",
        )
        assert outcome.observations == ()
        assert outcome.rejected[0].reason.value == "out_of_catalog"

    def test_budget_exceed_marks_status_but_keeps_findings(self) -> None:
        over = PeerAgentReport(
            run_id="run-1",
            findings=_report_with_sqli().findings,
            wall_seconds=10_000.0,
            cost_units=0.0,
            exit_code=0,
        )
        outcome = _service(FakeHarness(over)).launch(
            assessment_id="asmt-1",
            agent_name="strix",
            targets=("http://host.docker.internal:3000",),
            scope=_scope(),
            catalog=_catalog(),
            asset_type=AssetType.WEB_APP,
            actor="op",
            permit_id="p",
        )
        assert outcome.run.status is PeerRunStatus.BUDGET_EXCEEDED
        assert len(outcome.observations) == 1  # evidence preserved


class TestStop:
    def test_stop_terminates_and_records(self) -> None:
        harness = FakeHarness(_report_with_sqli())
        service = _service(harness)
        outcome = service.launch(
            assessment_id="asmt-1",
            agent_name="strix",
            targets=("http://host.docker.internal:3000",),
            scope=_scope(),
            catalog=_catalog(),
            asset_type=AssetType.WEB_APP,
            actor="op",
            permit_id="p",
        )
        assert (
            service.stop(run_id=outcome.run.id, actor="op", reason="emergency")
            is True
        )
        assert harness.terminated == [outcome.run.id]

    def test_stop_unknown_run_returns_false(self) -> None:
        service = _service(FakeHarness(_report_with_sqli()))
        assert service.stop(run_id="nope", actor="op", reason="x") is False
