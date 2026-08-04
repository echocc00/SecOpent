# tests/security/test_composition_root.py
"""Composition root assembles all security components (W2-A Task 6-7)."""
from __future__ import annotations

from secopent.application.audit_chain import AuditChain
from secopent.application.emergency_stop import EmergencyStop
from secopent.application.prompt_injection import (
    AgentAction,
    InjectionBlocked,
    PromptInjectionGuard,
)
from secopent.application.scope_enforcer import ScopeEnforcer
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.egress.egress_guard import EgressGuard
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
    assert isinstance(app.state.egress_guard, EgressGuard)
    assert isinstance(app.state.prompt_injection_guard, PromptInjectionGuard)

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
    assert api.app.state.egress_guard is app.state.egress_guard
    assert api.app.state.prompt_injection_guard is app.state.prompt_injection_guard


def test_prompt_injection_guard_blocks_protected_resource_action(tmp_path) -> None:
    """The assembled PIG rejects actions targeting protected resources (§12)."""
    import pytest

    engine = create_sqlite_engine(tmp_path / "t.db")
    app = create_app(engine=engine)
    guard: PromptInjectionGuard = app.state.prompt_injection_guard

    # An action that tries to modify the scope (protected) must be blocked.
    malicious = AgentAction(action_type="add_observation", target="scope", payload={})
    with pytest.raises(InjectionBlocked):
        guard.validate_action(malicious)

    # An allowed action on a non-protected target passes.
    ok = AgentAction(action_type="add_observation", target="finding", payload={})
    assert guard.validate_action(ok) is ok

