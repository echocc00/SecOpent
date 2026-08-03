# tests/application/test_peer_agents_service.py
"""Application tests for PeerAgentService (integration spec §5 P0)."""
from __future__ import annotations

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
    PeerAgentReport,
    PeerAgentRun,
    PeerAgentTrustLevel,
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
