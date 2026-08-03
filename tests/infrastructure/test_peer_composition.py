# tests/infrastructure/test_peer_composition.py
"""Composition wiring for peer agents (P2 Task 4).

Asserts that create_peer_agent_service returns a PeerAgentService whose
registry contains the strix descriptor with the correct version, license,
and trust level.
"""
from __future__ import annotations

from pathlib import Path

from secopent.application.peer_agents import PeerAgentService
from secopent.domain.peer_agents.models import PeerAgentTrustLevel
from secopent.infrastructure.peer_agents.composition import (
    STRIX_DEFAULT_BUDGET,
    STRIX_VERSION,
    create_peer_agent_service,
    strix_descriptor,
)


class TestStrixDescriptor:
    def test_version_and_license(self) -> None:
        desc = strix_descriptor()
        assert desc.name == "strix"
        assert desc.version == STRIX_VERSION
        assert desc.license == "Apache-2.0"
        assert desc.trust_level is PeerAgentTrustLevel.ADOPTED_EXTERNAL

    def test_default_budget(self) -> None:
        desc = strix_descriptor()
        assert desc.default_budget.max_wall_seconds == STRIX_DEFAULT_BUDGET.max_wall_seconds
        assert desc.default_budget.max_cost_units == STRIX_DEFAULT_BUDGET.max_cost_units


class TestCreatePeerAgentService:
    def _make_service(self, tmp_path: Path) -> PeerAgentService:
        from secopent.application.audit import AuditService
        from secopent.application.ports.peer_runs import InMemoryPeerRunRepository

        return create_peer_agent_service(
            audit=AuditService(repo=_FakeAuditRepo()),
            runs=InMemoryPeerRunRepository(),
            llm_provider="openai/gpt-4o-mini",
            secret_lookup={"LLM_API_KEY": "sk-test"},
            workdir_root=tmp_path,
        )

    def test_returns_peer_agent_service(self, tmp_path: Path) -> None:
        service = self._make_service(tmp_path)
        assert isinstance(service, PeerAgentService)

    def test_registry_contains_strix(self, tmp_path: Path) -> None:
        service = self._make_service(tmp_path)
        desc = service.registry.get("strix")
        assert desc is not None
        assert desc.name == "strix"
        assert desc.version == "1.4.1"
        assert desc.license == "Apache-2.0"
        assert desc.trust_level is PeerAgentTrustLevel.ADOPTED_EXTERNAL

    def test_unregistered_agent_raises(self, tmp_path: Path) -> None:
        """Launching an unknown agent name raises PeerAgentNotRegistered."""
        from secopent.domain.catalog.models import AssetType, TestCatalog
        from secopent.domain.peer_agents.models import PeerAgentNotRegistered
        from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot
        from datetime import UTC, datetime

        import pytest

        service = self._make_service(tmp_path)
        scope = ScopeSnapshot(
            id="snap", project_id="proj",
            include=("host.docker.internal",), exclude=(), ports=(3000,),
            limits=ScopeLimits(requests_per_second=5.0, concurrency=3, max_requests=1000),
            approved_by="a", approved_at=datetime(2026, 1, 1, tzinfo=UTC),
            digest="sha256:" + "0" * 64,
        )
        with pytest.raises(PeerAgentNotRegistered):
            service.launch(
                assessment_id="a", agent_name="nonexistent",
                targets=("http://host.docker.internal:3000",),
                scope=scope, catalog=TestCatalog(version="v1", mappings={}),
                asset_type=AssetType.WEB_APP, actor="op", permit_id="p",
            )


class _FakeAuditRepo:
    """Minimal audit repo for composition tests."""

    def __init__(self) -> None:
        self._events: list[object] = []

    def add(self, event: object) -> None:
        self._events.append(event)

    def list_events(self) -> list[object]:
        return list(self._events)

    def last_hash(self) -> str:
        from secopent.domain.audit.models import GENESIS_HASH
        return GENESIS_HASH
