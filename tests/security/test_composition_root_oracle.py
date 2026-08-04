"""Composition root assembles OracleService + canary singleton (W3-A T6)."""
from __future__ import annotations

from secopent.application.canary import CanaryTokenManager
from secopent.application.oracle_service import OracleService
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.oracle.verifier_factory import RescanVerifierFactory
from secopent.interfaces.api.main import create_app


def test_app_state_has_oracle_service(tmp_path) -> None:
    engine = create_sqlite_engine(tmp_path / "t.db")
    app = create_app(engine=engine)

    assert isinstance(app.state.oracle, OracleService)
    assert isinstance(app.state.canary, CanaryTokenManager)
    # The verifier factory is the concrete RescanVerifierFactory.
    assert isinstance(app.state.oracle._verifier_factory, RescanVerifierFactory)


def test_canary_uses_shared_audit_chain(tmp_path) -> None:
    """canary singleton audits to the shared signed AuditChain."""
    engine = create_sqlite_engine(tmp_path / "t.db")
    app = create_app(engine=engine)
    canary: CanaryTokenManager = app.state.canary
    chain = app.state.audit_chain

    canary.generate(actor="oracle", candidate_id="cand-1")

    assert any(e.action == "canary.generated" for e in chain.events())
    assert chain.verify() is True


def test_oracle_shared_with_api_subapp(tmp_path) -> None:
    """The /api sub-app sees the same oracle + canary singletons."""
    engine = create_sqlite_engine(tmp_path / "t.db")
    app = create_app(engine=engine)
    api = next(m for m in app.routes if getattr(m, "path", "") == "/api")

    assert api.app.state.oracle is app.state.oracle
    assert api.app.state.canary is app.state.canary
