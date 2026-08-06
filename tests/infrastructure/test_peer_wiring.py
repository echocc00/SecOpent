"""Phase 2.2: real peer-agent backends wiring.

Asserts the composition root in ``interfaces/api/main.py`` switches to the
real ``ContainerPeerAgentHarness`` (factory default) when ``LLM_API_KEY`` is
present, and degrades to ``NullPeerAgentHarness`` with a warning when the key
is missing. The disabled path (no ``SECOPTENT_PEER_AGENTS_ENABLED``) still
yields ``None`` - that contract is covered by ``test_peer_agent_wiring.py``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from secopent.application.peer_agents import PeerAgentService
from secopent.infrastructure.peer_agents.harness import ContainerPeerAgentHarness
from secopent.infrastructure.peer_agents.null_harness import NullPeerAgentHarness
from secopent.interfaces.api.main import create_app


def _peer_harness(app: object) -> object:
    """Read the wired harness off the service (private attr; test-only)."""
    service = getattr(app.state, "peer_agent_service", None)
    assert isinstance(service, PeerAgentService)
    return service._harness  # type: ignore[attr-defined]


def test_real_harness_when_llm_key_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """With LLM_API_KEY set, the factory default ContainerPeerAgentHarness is
    wired - real strix/shannon backends are reachable at launch time."""
    monkeypatch.setenv("SECOPTENT_PEER_AGENTS_ENABLED", "1")
    monkeypatch.setenv("LLM_API_KEY", "sk-test-real")
    monkeypatch.delenv("SECOPTENT_ENABLE_SHANNON", raising=False)

    app = create_app()
    harness = _peer_harness(app)
    assert isinstance(harness, ContainerPeerAgentHarness)
    # And strix is registered (real backend path).
    service = app.state.peer_agent_service
    assert service is not None
    assert service.registry.get("strix") is not None


def test_null_harness_fallback_without_llm_key(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Without LLM_API_KEY, the service still constructs but degrades to
    NullPeerAgentHarness and logs a warning explaining how to enable real
    backends. Peer launches return empty outcomes instead of KeyErroring."""
    monkeypatch.setenv("SECOPTENT_PEER_AGENTS_ENABLED", "1")
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    with caplog.at_level("WARNING", logger="secopent.peer_agents"):
        app = create_app()

    harness = _peer_harness(app)
    assert isinstance(harness, NullPeerAgentHarness)
    # The warning must explain the fallback so operators know what to fix.
    assert any(
        "LLM_API_KEY" in rec.message and "NullPeerAgentHarness" in rec.message
        for rec in caplog.records
    ), f"expected fallback warning, got: {[r.message for r in caplog.records]}"


def test_shannon_opt_in_when_enabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """SECOPTENT_ENABLE_SHANNON=true + repo path registers shannon on the
    real harness path."""
    repo = tmp_path / "shannon-repo"
    repo.mkdir()
    monkeypatch.setenv("SECOPTENT_PEER_AGENTS_ENABLED", "1")
    monkeypatch.setenv("LLM_API_KEY", "sk-test-real")
    monkeypatch.setenv("SECOPTENT_ENABLE_SHANNON", "true")
    monkeypatch.setenv("SECOPTENT_SHANNON_REPO", str(repo))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    app = create_app()
    service = app.state.peer_agent_service
    assert service is not None
    assert isinstance(service._harness, ContainerPeerAgentHarness)  # type: ignore[attr-defined]
    assert service.registry.get("shannon") is not None
