"""Composition factory wiring: SQL vs InMemory loop repos (v0.7.8 Task 3).

Proves ``create_loop_state_repo`` / ``create_loop_step_repo`` select the
SQLAlchemy-backed repos when handed a real ``Database`` and the in-memory
stores when handed ``None``, and that the orchestrator persists loops through
the SQL-backed state/step repos (phase + step aggregation both round-trip).
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import create_engine

from secopent.application.audit import AuditService
from secopent.application.reasoning_loop.context_builder import (
    DefaultLoopContextBuilder,
)
from secopent.application.reasoning_loop.feedback import LoopFeedback
from secopent.application.reasoning_loop.in_memory_state import (
    InMemoryLoopStateRepository,
    InMemoryLoopStepRepository,
)
from secopent.application.reasoning_loop.mock_proposer import MockLoopActionProposer
from secopent.application.reasoning_loop.orchestrator import ReasoningLoopOrchestrator
from secopent.application.reasoning_loop.permit_gate import PermitGateImpl
from secopent.application.reasoning_loop.policy_gate import PolicyGateImpl
from secopent.application.reasoning_loop.schema_gate import SchemaGateImpl
from secopent.domain.catalog.models import TestCatalog
from secopent.domain.policy.models import ExecutionMode, PolicyDecision
from secopent.domain.reasoning_loop.models import (
    AvailableCapability,
    LoopActionType,
    LoopId,
    LoopPhase,
    LoopPlan,
    LoopState,
    LoopTerminationPolicy,
    ProposeAction,
)
from secopent.infrastructure.db.session import Database
from secopent.infrastructure.permits.permit_signer import (
    PermitSigner,
    PermitVerifier,
)
from secopent.infrastructure.reasoning_loop.repo_factory import (
    create_loop_state_repo,
    create_loop_step_repo,
)

_T0 = datetime(2026, 1, 1, tzinfo=UTC)


@dataclass
class _FakeAuditRepo:
    events: list[Any] | None = None

    def __post_init__(self) -> None:
        self.events: list[Any] = []

    def add(self, e: Any) -> None:
        self.events.append(e)

    def list_events(self) -> list[Any]:
        return list(self.events)

    def last_hash(self) -> str:
        if not self.events:
            return "0" * 64
        return str(self.events[-1].event_hash).removeprefix("sha256:")


def _allow_all_engine(
    request: Any,
    *,
    scope: Any,
    mode: Any,
    approved_risks: Any,
    approved_capabilities: Any,
) -> PolicyDecision:
    return PolicyDecision(allowed=True, reason="ok")


def _tool_capabilities(assessment_id: str) -> tuple[AvailableCapability, ...]:
    return (
        AvailableCapability(
            capability_id="nuclei",
            kind="tool",
            summary="template-driven web/API vulnerability scanner",
            risk_class="active",
            cwe=("CWE-89", "CWE-79"),
        ),
    )


def _permit_gate() -> PermitGateImpl:
    signer = PermitSigner()
    verifier = PermitVerifier(signer.public_key_bytes())
    return PermitGateImpl(ttl_seconds=900, signer=signer, verifier=verifier)


def _scripted_action(rationale: str = "r" * 80) -> ProposeAction:
    return ProposeAction(
        action_type=LoopActionType.RUN_TOOL,
        payload={"tool_id": "nuclei", "parameters": {}},
        rationale=rationale,
        confidence=0.5,
    )


def _plan(lid: LoopId) -> LoopPlan:
    return LoopPlan(
        plan_id="lp-1",
        loop_id=lid,
        assessment_id="asmt-1",
        termination_policy=LoopTerminationPolicy.default(),
        policy_snapshot="sha256:" + "0" * 64,
        created_at=_T0,
    )


def _make_orchestrator(
    *,
    state_repo: object,
    step_repo: object,
    script: Iterable[ProposeAction] = (),
) -> ReasoningLoopOrchestrator:
    catalog = TestCatalog(version="t-1", mappings={})
    builder = DefaultLoopContextBuilder(
        catalog=catalog,
        state_repo=state_repo,
        asset_subgraph_provider=lambda aid: (),  # type: ignore[arg-type, return-value]
        observation_provider=lambda lid: (),  # type: ignore[arg-type, return-value]
        tool_provider=_tool_capabilities,
    )
    proposer = MockLoopActionProposer(script=script)
    audit = AuditService(_FakeAuditRepo())
    return ReasoningLoopOrchestrator(
        state_repo=state_repo,
        step_repo=step_repo,
        context_builder=builder,
        proposer=proposer,
        schema_gate=SchemaGateImpl(),
        policy_gate=PolicyGateImpl(
            scope=None,  # type: ignore[arg-type]  # allow-all engine ignores scope
            mode=ExecutionMode.SCOPE_AUTOPILOT,
            approved_risks=frozenset(),
            approved_capabilities=frozenset(),
            engine=_allow_all_engine,
        ),
        permit_gate=_permit_gate(),
        feedback=LoopFeedback(),
        audit=audit,
        clock=lambda: _T0,
    )


@pytest.fixture
def database() -> Database:
    """A Database over a fresh in-memory SQLite engine with all tables created.

    ``Database.__init__`` calls ``init_db`` which ``create_all``s every table
    (incl. the loop tables) on a fresh DB, so the SQL repos have a valid schema.
    """
    engine = create_engine("sqlite:///:memory:")
    db = Database(engine)
    yield db
    engine.dispose()


class TestFactoryDiscriminator:
    def test_none_db_returns_in_memory_state_repo(self) -> None:
        repo = create_loop_state_repo(None)
        assert isinstance(repo, InMemoryLoopStateRepository)
        assert not isinstance(repo, type(None))

    def test_none_db_returns_in_memory_step_repo(self) -> None:
        repo = create_loop_step_repo(None)
        assert isinstance(repo, InMemoryLoopStepRepository)

    def test_sql_database_returns_sqlalchemy_state_repo(
        self, database: Database
    ) -> None:
        from secopent.infrastructure.reasoning_loop.sqlalchemy_state import (
            SqlAlchemyLoopStateRepository,
        )

        repo = create_loop_state_repo(database)
        assert isinstance(repo, SqlAlchemyLoopStateRepository)
        repo._session.close()  # noqa: SLF001 - test teardown of factory-opened session

    def test_sql_database_returns_sqlalchemy_step_repo(self, database: Database) -> None:
        from secopent.infrastructure.reasoning_loop.sqlalchemy_state import (
            SqlAlchemyLoopStepRepository,
        )

        repo = create_loop_step_repo(database)
        assert isinstance(repo, SqlAlchemyLoopStepRepository)
        repo._session.close()  # noqa: SLF001 - test teardown of factory-opened session


class TestOrchestratorPersistsThroughSqlRepos:
    def test_create_and_run_steps_persist_phase_and_steps(
        self, database: Database
    ) -> None:
        state_repo = create_loop_state_repo(database)
        step_repo = create_loop_step_repo(database)
        try:
            orch = _make_orchestrator(
                state_repo=state_repo,
                step_repo=step_repo,
                script=[_scripted_action(), _scripted_action()],
            )
            lid = LoopId(value="abcd1234")

            orch.create_loop(_plan(lid), catalog_required_remaining=frozenset())
            assert state_repo.get(lid) is not None
            assert state_repo.get(lid).phase is LoopPhase.INITIALIZING

            result = orch.run_step(loop_id=lid)
            assert result.phase is LoopPhase.RUNNING
            # Phase advanced through the SQL-backed state repo.
            assert state_repo.get(lid).phase is LoopPhase.RUNNING
            # Steps aggregated through the SQL-backed step repo.
            assert len(step_repo.list_for_loop(lid)) == 1

            orch.run_step(loop_id=lid)
            assert len(step_repo.list_for_loop(lid)) == 2
        finally:
            state_repo._session.close()  # noqa: SLF001
            step_repo._session.close()  # noqa: SLF001

    def test_create_loop_sets_catalog_remaining(self, database: Database) -> None:
        state_repo = create_loop_state_repo(database)
        step_repo = create_loop_step_repo(database)
        try:
            orch = _make_orchestrator(state_repo=state_repo, step_repo=step_repo)
            lid = LoopId(value="efefefef")
            orch.create_loop(
                _plan(lid), catalog_required_remaining=frozenset({"web:sqli"})
            )
            state = state_repo.get(lid)
            assert state is not None
            assert isinstance(state, LoopState)
            assert state.catalog_required_remaining == frozenset({"web:sqli"})
        finally:
            state_repo._session.close()  # noqa: SLF001
            step_repo._session.close()  # noqa: SLF001
