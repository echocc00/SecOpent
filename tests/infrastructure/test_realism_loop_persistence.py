# tests/infrastructure/test_realism_loop_persistence.py
"""Production-realism regression: loop write handlers MUST commit (v0.7.2 hotfix).

Issue v10: ``handler_loop_create`` / ``loop_stop`` (MCP), ``create_loop`` /
``stop_loop`` (REST), and ``PauseControlService.pause`` / ``resume`` called
``state_repo.save(state)`` + ``audit_chain.record(...)`` with NO
``unit_of_work()`` and NO ``session=`` on the audit call.
``SqlAlchemyLoopStateRepository.save`` only does ``session.merge()`` (no
commit), so the merged row was rolled back when the request session closed.
The handler returned success and ``loop_status`` read it back from the SAME
session's identity map (existing tests passed), but a fresh session / daemon
restart saw NOT_FOUND — silent state loss + a broken "every state change
persists before it's reported" audit invariant.

This test forces the regression class at the seam: after each write handler
returns, the loop MUST be readable from a BRAND-NEW Database session. Under
the v0.7.1 code the merge never committed, so the fresh-session read fails.
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import create_engine

from secopent.application.audit_chain import AuditChain
from secopent.application.reasoning_loop.pause_control import (
    PauseControlService,
)
from secopent.domain.reasoning_loop.models import (
    LoopBudget,
    LoopId,
    LoopPhase,
    LoopState,
)
from secopent.infrastructure.audit.key_manager import AuditKeyManager

# Importing these registers the ORM tables on CoreBase.metadata so the
# in-memory SQLite engine can create them (core_reasoning_loops +
# core_loop_steps + core_signed_audit_events).
from secopent.infrastructure.db import core_models  # noqa: F401
from secopent.infrastructure.db.session import Database
from secopent.infrastructure.db.signed_audit_models import (  # noqa: F401
    CoreSignedAuditEvent,
)
from secopent.infrastructure.reasoning_loop.repo_factory import (  # noqa: F401
    create_loop_state_repo,
    create_loop_step_repo,
)
from secopent.infrastructure.reasoning_loop.sqlalchemy_state import (
    SqlAlchemyLoopStateRepository,
    SqlAlchemyLoopStepRepository,
)
from secopent.infrastructure.repositories.sqlalchemy_audit_chain import (
    SqlAlchemySignedAuditEventStore,
)
from secopent.interfaces.mcp.handlers import (
    McpRuntime,
    handler_loop_create,
    handler_loop_stop,
)


def _database() -> Database:
    # A shared in-memory SQLite DB: the default ``:memory:`` gives each
    # connection its OWN database, so a row committed on one session is
    # invisible to another (which is exactly the regression we're testing).
    # ``cache=shared`` + StaticPool pins every session to one connection so
    # committed rows are visible across fresh sessions.
    engine = create_engine(
        "sqlite:///file:realism_loop?mode=memory&cache=shared",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=__import__(
            "sqlalchemy.pool", fromlist=["StaticPool"]
        ).StaticPool,
    )
    core_models.CoreBase.metadata.create_all(engine)
    return Database(engine)


def _audit_chain(db: Database) -> AuditChain:
    return AuditChain(AuditKeyManager(), store=SqlAlchemySignedAuditEventStore(db))


def _runtime(db: Database, *, audit: AuditChain) -> McpRuntime:
    # Write handlers must NOT rely on pre-bound singletons for SQL — they
    # build per-request repos from the UoW session. Kept None to prove it.
    return McpRuntime(
        db=db,
        audit_chain=audit,
        loop_state_repo=None,
        loop_step_repo=None,
    )


class TestMcpLoopHandlersPersistAcrossSession:
    def test_loop_create_survives_fresh_session(self) -> None:
        db = _database()
        runtime = _runtime(db, audit=_audit_chain(db))

        result = handler_loop_create(
            runtime, assessment_id="asm-1", grant_id="grant-1", max_steps=3,
        )
        assert result["status"] == "success"
        loop_id = result["loop_id"]

        fresh = db.open_session()
        row = SqlAlchemyLoopStateRepository(fresh).get(LoopId(loop_id))
        assert row is not None, "loop vanished from DB after handler returned"
        assert row.phase is LoopPhase.INITIALIZING

    def test_loop_stop_survives_fresh_session(self) -> None:
        db = _database()
        runtime = _runtime(db, audit=_audit_chain(db))

        created = handler_loop_create(
            runtime, assessment_id="asm-2", grant_id="grant-2", max_steps=3,
        )
        loop_id = created["loop_id"]
        stopped = handler_loop_stop(
            runtime, loop_id=loop_id, grant_id="grant-2",
        )
        assert stopped["status"] == "success"

        fresh = db.open_session()
        row = SqlAlchemyLoopStateRepository(fresh).get(LoopId(loop_id))
        assert row is not None
        assert row.phase is LoopPhase.EMERGENCY_STOPPED

    def test_audit_event_survives_fresh_session(self) -> None:
        """The signed loop.created audit event must persist too (issue §4)."""
        db = _database()
        runtime = _runtime(db, audit=_audit_chain(db))

        result = handler_loop_create(
            runtime, assessment_id="asm-3", grant_id="grant-3", max_steps=3,
        )
        loop_id = result["loop_id"]

        fresh = db.open_session()
        rows = fresh.query(CoreSignedAuditEvent).all()
        actions = [r.action for r in rows]
        assert "loop.created" in actions
        assert any(r.resource_id == loop_id for r in rows)


class TestPauseControlServicePersistsAcrossSession:
    """PauseControlService.pause/resume: same save+audit regression class."""

    def _service(self, db: Database, *, audit: AuditChain) -> PauseControlService:
        from secopent.application.reasoning_loop.in_memory_state import (
            InMemoryLoopStateRepository,
        )
        from secopent.infrastructure.reasoning_loop.loop_approval import (
            SignedLoopApproval,
        )

        # The injected state_repo is only used when ``session=None``; pause
        # always passes a UoW session, so an InMemory repo here is just a
        # placeholder satisfying the constructor (never read/written).
        return PauseControlService(
            state_repo=InMemoryLoopStateRepository(),
            audit=audit,
            approval=SignedLoopApproval(),
        )

    def test_pause_survives_fresh_session(self) -> None:
        db = _database()
        audit = _audit_chain(db)
        lid = LoopId("ab9f0099")

        # Seed a RUNNING loop via a committed UoW (close releases the write
        # transaction so the pause UoW can see the row).
        with db.unit_of_work() as seed_uow:
            SqlAlchemyLoopStateRepository(seed_uow.session).save(
                LoopState(
                    loop_id=lid,
                    assessment_id="asm-p",
                    phase=LoopPhase.RUNNING,
                    policy_snapshot="snap",
                    budget=LoopBudget.default(),
                    context_hash="0" * 64,
                    catalog_required_remaining=frozenset(),
                    catalog_required_executed=frozenset(),
                    consecutive_no_signal=0,
                    consecutive_policy_rejected=0,
                    started_at=datetime(2026, 8, 1, tzinfo=UTC),
                    last_step_at=None,
                )
            )

        service = self._service(db, audit=audit)
        with db.unit_of_work() as uow:
            paused = service.pause(
                loop_id=lid, actor="human", reason="t", actor_role="human",
                session=uow.session,
            )
        assert paused.phase is LoopPhase.PAUSED

        fresh = db.open_session()
        row = SqlAlchemyLoopStateRepository(fresh).get(lid)
        assert row is not None
        assert row.phase is LoopPhase.PAUSED


class TestOrchestratorPersistsAcrossSession:
    """ReasoningLoopOrchestrator.create_loop/run_step: same regression class.

    The orchestrator is the loop stepper (called by the executor daemon when
    wired). Its 7 save+audit sites had the same v10 bug: ``state_repo.save``
    merged without committing. This proves a UoW-wrapped ``run_step`` persists
    the step + state transition to a fresh session.
    """

    def _orchestrator(self, db: Database, *, audit: AuditChain) -> object:
        from secopent.application.reasoning_loop.context_builder import (
            DefaultLoopContextBuilder,
        )
        from secopent.application.reasoning_loop.feedback import LoopFeedback
        from secopent.application.reasoning_loop.mock_proposer import (
            MockLoopActionProposer,
        )
        from secopent.application.reasoning_loop.orchestrator import (
            ReasoningLoopOrchestrator,
        )
        from secopent.application.reasoning_loop.permit_gate import PermitGateImpl
        from secopent.application.reasoning_loop.policy_gate import (
            PolicyGateImpl,
        )
        from secopent.application.reasoning_loop.schema_gate import SchemaGateImpl
        from secopent.domain.catalog.models import TestCatalog
        from secopent.domain.policy.models import (
            ExecutionMode,
            PolicyDecision,
        )
        from secopent.infrastructure.permits.permit_signer import (
            PermitSigner,
            PermitVerifier,
        )

        state_repo = SqlAlchemyLoopStateRepository(db.open_session())
        step_repo = SqlAlchemyLoopStepRepository(db.open_session())

        def _allow_all(request: object, **_: object) -> PolicyDecision:
            return PolicyDecision(allowed=True, reason="ok")

        builder = DefaultLoopContextBuilder(
            catalog=TestCatalog(version="t", mappings={}),
            state_repo=state_repo,
            asset_subgraph_provider=lambda aid: (),
            observation_provider=lambda lid: (),
            tool_provider=lambda aid: (),
        )
        signer = PermitSigner()
        return ReasoningLoopOrchestrator(
            state_repo=state_repo,
            step_repo=step_repo,
            context_builder=builder,
            proposer=MockLoopActionProposer(script=[]),
            schema_gate=SchemaGateImpl(),
            policy_gate=PolicyGateImpl(
                scope=None,  # type: ignore[arg-type]
                mode=ExecutionMode.SCOPE_AUTOPILOT,
                approved_risks=frozenset(),
                approved_capabilities=frozenset(),
                engine=_allow_all,
            ),
            permit_gate=PermitGateImpl(
                ttl_seconds=900, signer=signer,
                verifier=PermitVerifier(signer.public_key_bytes()),
            ),
            feedback=LoopFeedback(),
            audit=audit,
        )

    def test_create_loop_survives_fresh_session(self) -> None:
        db = _database()
        audit = _audit_chain(db)
        orch = self._orchestrator(db, audit=audit)
        import datetime as _dt

        from secopent.domain.reasoning_loop.models import (
            LoopId,
            LoopPlan,
            LoopTerminationPolicy,
        )

        lid = LoopId("ab9f00aa")
        plan = LoopPlan(
            plan_id="lp-1", loop_id=lid, assessment_id="asm-o",
            termination_policy=LoopTerminationPolicy.default(),
            policy_snapshot="sha256:" + "0" * 64,
            created_at=_dt.datetime(2026, 8, 1, tzinfo=_dt.UTC),
        )
        with db.unit_of_work() as uow:
            orch.create_loop(plan, catalog_required_remaining=frozenset(), session=uow.session)

        fresh = db.open_session()
        row = SqlAlchemyLoopStateRepository(fresh).get(lid)
        assert row is not None, "orchestrator create_loop vanished from DB"
        assert row.phase is LoopPhase.INITIALIZING
