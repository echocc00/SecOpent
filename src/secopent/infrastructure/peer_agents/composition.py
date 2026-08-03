# src/secopent/infrastructure/peer_agents/composition.py
"""Composition wiring for peer agents (P2).

Creates a fully wired PeerAgentService with the strix descriptor registered
and a ContainerPeerAgentHarness backed by StrixBackend. The factory is the
single point where infrastructure dependencies (executor, backend, image
catalog) are assembled - application code never imports them directly.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ...application.audit import AuditService
from ...application.peer_agents import PeerAgentService
from ...application.ports.repositories import PeerRunRepository
from ...domain.peer_agents.models import (
    PeerAgentBudget,
    PeerAgentDescriptor,
    PeerAgentTrustLevel,
)
from ...domain.peer_agents.registry import PeerAgentRegistry
from ..adapters.subprocess_executor import SubprocessContainerExecutor
from .harness import ContainerPeerAgentHarness
from .image_catalog import PEER_IMAGE_CATALOG
from .strix_backend import StrixBackend

STRIX_VERSION = "1.4.1"  # pinned to worker Dockerfile strix-agent version
STRIX_DEFAULT_BUDGET = PeerAgentBudget(
    max_wall_seconds=60 * 60,  # 1h wall clock
    max_cost_units=200.0,  # USD cost class cap (self-reported)
)


def strix_descriptor() -> PeerAgentDescriptor:
    """Build the strix descriptor from the pinned image catalog entry."""
    image = PEER_IMAGE_CATALOG.get("strix")
    digest = f"{image.name}@{image.digest}" if image and image.digest else ""
    return PeerAgentDescriptor(
        name="strix",
        version=STRIX_VERSION,
        license="Apache-2.0",
        trust_level=PeerAgentTrustLevel.ADOPTED_EXTERNAL,
        capabilities=("web", "api"),
        cost_class="llm_tokens",
        default_budget=STRIX_DEFAULT_BUDGET,
        image_digest=digest,
    )


def create_peer_agent_service(
    *,
    audit: AuditService,
    runs: PeerRunRepository,
    llm_provider: str,
    secret_lookup: Mapping[str, str],
    workdir_root: Path,
) -> PeerAgentService:
    """Wire up a PeerAgentService with all adopted peer agents registered."""
    registry = PeerAgentRegistry()
    registry.register(strix_descriptor())
    harness = ContainerPeerAgentHarness(
        executor=SubprocessContainerExecutor(
            default_timeout=STRIX_DEFAULT_BUDGET.max_wall_seconds,
        ),
        backends={
            "strix": StrixBackend(
                llm_provider=llm_provider,
                secret_lookup=secret_lookup,
            ),
        },
        workdir_root=workdir_root,
    )
    return PeerAgentService(
        registry=registry,
        harness=harness,
        audit=audit,
        runs=runs,
    )
