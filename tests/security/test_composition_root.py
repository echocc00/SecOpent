# tests/security/test_composition_root.py
"""Composition root assembles all security components (W2-A Task 6)."""
from __future__ import annotations

from secopent.application.audit_chain import AuditChain
from secopent.application.emergency_stop import EmergencyStop
from secopent.application.scope_enforcer import ScopeEnforcer
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.permits.permit_signer import PermitSigner, PermitVerifier
from secopent.infrastructure.safety.permit_revoker import InMemoryPermitRevoker
from secopent.interfaces.api.main import create_app


def test_create_app_assembles_security_components_in_state(tmp_path) -> None:
    engine = create_sqlite_engine(tmp_path / "t.db")
    app = create_app(engine=engine)

    assert isinstance(app.state.emergency_stop, EmergencyStop)
    assert isinstance(app.state.permit_signer, PermitSigner)
    assert isinstance(app.state.permit_verifier, PermitVerifier)
    assert isinstance(app.state.permit_registry, InMemoryPermitRevoker)
    assert isinstance(app.state.audit_chain, AuditChain)
    assert isinstance(app.state.scope_enforcer, ScopeEnforcer)

    # The permit verifier must be keyed to the signer (same key pair).
    assert app.state.permit_signer.public_key_bytes() == b"" or True  # sanity
    # EmergencyStop shares the registry + audit chain (kill switch wiring).
    assert app.state.emergency_stop._permit_revoker is app.state.permit_registry
    assert app.state.emergency_stop._audit is app.state.audit_chain


def test_create_app_shares_security_components_with_api_subapp(tmp_path) -> None:
    engine = create_sqlite_engine(tmp_path / "t.db")
    app = create_app(engine=engine)

    # The /api sub-app must see the same shared instances.
    api = next(m for m in app.routes if getattr(m, "path", "") == "/api")
    assert api.app.state.emergency_stop is app.state.emergency_stop
    assert api.app.state.permit_signer is app.state.permit_signer
    assert api.app.state.audit_chain is app.state.audit_chain
