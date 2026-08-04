"""PeerAgentService composition-root wiring (W4-A T5)."""
from __future__ import annotations

import pytest

from secopent.application.peer_agents import PeerAgentService
from secopent.interfaces.api.main import create_app


def test_service_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECOPTENT_PEER_AGENTS_ENABLED", raising=False)
    app = create_app()
    assert getattr(app.state, "peer_agent_service", None) is None


def test_service_enabled_when_flag_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECOPTENT_PEER_AGENTS_ENABLED", "1")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    app = create_app()
    service = getattr(app.state, "peer_agent_service", None)
    assert isinstance(service, PeerAgentService)
    # strix is registered by default; shannon is opt-in.
    assert service.registry.get("strix") is not None
    assert service.registry.get("shannon") is None


def test_service_propagated_to_api_subapp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECOPTENT_PEER_AGENTS_ENABLED", "1")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    app = create_app()
    # The /api sub-app must share the same service instance.
    api_app = next(
        r.app for r in app.routes if getattr(r, "path", "") == "/api"
    )
    assert api_app.state.peer_agent_service is app.state.peer_agent_service
