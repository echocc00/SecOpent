# src/secopent/infrastructure/peer_agents/composition.py
"""Composition wiring for peer agents (P2).

Creates a fully wired PeerAgentService with the strix descriptor registered
and a ContainerPeerAgentHarness backed by StrixBackend. The factory is the
single point where infrastructure dependencies (executor, backend, image
catalog) are assembled - application code never imports them directly.

P3: Shannon registration is opt-in (enable_shannon=True + repo path given).
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ...application.peer_agents import PeerAgentHarness, PeerAgentService
from ...application.ports.audit import AuditRecorder
from ...application.ports.repositories import PeerRunRepository
from ...domain.peer_agents.models import (
    PeerAgentBudget,
    PeerAgentDescriptor,
    PeerAgentTrustLevel,
)
from ...domain.peer_agents.registry import PeerAgentRegistry
from ..adapters.image_catalog import ImageRef
from ..adapters.subprocess_executor import SubprocessContainerExecutor
from .harness import ContainerPeerAgentHarness, PeerAgentBackend
from .image_catalog import PEER_IMAGE_CATALOG
from .ptai_backend import PtaiBackend
from .shannon_backend import ShannonBackend
from .strix_backend import StrixBackend

STRIX_VERSION = "1.4.1"  # pinned to worker Dockerfile strix-agent version
STRIX_DEFAULT_BUDGET = PeerAgentBudget(
    max_wall_seconds=60 * 60,  # 1h wall clock
    max_cost_units=200.0,  # USD cost class cap (self-reported)
)
SHANNON_VERSION = "2.0"
SHANNON_DEFAULT_BUDGET = PeerAgentBudget(
    max_wall_seconds=60 * 60,  # 1h wall clock
    max_cost_units=200.0,  # LLM tokens cost class
)
# ptai version from the A4 spike (sepcs/2026-07-27-a4-ptai-spike-findings.md):
# `pip show ptai` reported 1.1.0, MIT, 0xSteph, https://pentestai.xyz.
PTAI_VERSION = "1.1.0"
PTAI_DEFAULT_BUDGET = PeerAgentBudget(
    max_wall_seconds=60 * 60,  # 1h wall clock
    max_cost_units=200.0,  # LLM tokens cost class (self-reported; ptai does
    # not self-report cost, so wall + external metering is authoritative)
)


def _image_ref(image: ImageRef | None) -> str:
    """Resolve an image catalog entry to a docker-pullable reference.

    Digest-pinned (``name@sha256:...``) when a digest is recorded; falls back
    to tag-only (``name:tag``) when the digest is empty - the executor's
    digest check skips tag-only refs (no ``@``), so locally-built images work
    until a registry push records a digest to pin.
    """
    if image is None:
        return ""
    if image.digest:
        return f"{image.name}@{image.digest}"
    return f"{image.name}:{image.tag}"


def strix_descriptor() -> PeerAgentDescriptor:
    """Build the strix descriptor from the pinned image catalog entry."""
    return PeerAgentDescriptor(
        name="strix",
        version=STRIX_VERSION,
        license="Apache-2.0",
        trust_level=PeerAgentTrustLevel.ADOPTED_EXTERNAL,
        capabilities=("web", "api"),
        cost_class="llm_tokens",
        default_budget=STRIX_DEFAULT_BUDGET,
        image_digest=_image_ref(PEER_IMAGE_CATALOG.get("strix")),
    )


def shannon_descriptor() -> PeerAgentDescriptor:
    """Build the shannon descriptor from the image catalog entry."""
    return PeerAgentDescriptor(
        name="shannon",
        version=SHANNON_VERSION,
        license="AGPL-3.0",
        trust_level=PeerAgentTrustLevel.ADOPTED_EXTERNAL,
        capabilities=("web", "whitebox"),
        cost_class="llm_tokens",
        default_budget=SHANNON_DEFAULT_BUDGET,
        image_digest=_image_ref(PEER_IMAGE_CATALOG.get("shannon")),
    )


def ptai_descriptor() -> PeerAgentDescriptor:
    """Build the ptai descriptor from the image catalog entry.

    ptai (MIT, 0xSteph) is an autonomous AI pentest agent (A4 spike
    re-scope). The catalog entry carries ``digest=""`` until the first
    Linux build of peer-worker-ptai records a manifest-list digest.
    """
    return PeerAgentDescriptor(
        name="ptai",
        version=PTAI_VERSION,
        license="MIT",
        trust_level=PeerAgentTrustLevel.ADOPTED_EXTERNAL,
        capabilities=("web", "network"),
        cost_class="llm_tokens",
        default_budget=PTAI_DEFAULT_BUDGET,
        image_digest=_image_ref(PEER_IMAGE_CATALOG.get("ptai")),
    )


def create_peer_agent_service(
    *,
    audit: AuditRecorder,
    runs: PeerRunRepository,
    llm_provider: str,
    secret_lookup: Mapping[str, str],
    workdir_root: Path,
    harness: PeerAgentHarness | None = None,
    enable_shannon: bool = False,
    shannon_repo_path: Path | None = None,
    shannon_llm_key_name: str = "ANTHROPIC_API_KEY",
    enable_ptai: bool = False,
    ptai_llm_key_name: str = "LLM_API_KEY",
) -> PeerAgentService:
    """Wire up a PeerAgentService with all adopted peer agents registered.

    Shannon is only registered when ``enable_shannon`` is True AND
    ``shannon_repo_path`` is provided (the target repo working copy source).
    ptai is only registered when ``enable_ptai`` is True (Linux-only image;
    the peer-worker-ptai image must be built on a Linux worker - the Windows
    dev environment cannot ``pip install ptai`` with deps).

    ``harness`` overrides the default ``ContainerPeerAgentHarness`` - pass a
    ``NullPeerAgentHarness`` when Docker/images are unavailable so the service
    degrades to empty outcomes instead of failing at launch.
    """
    registry = PeerAgentRegistry()
    registry.register(strix_descriptor())

    backends: dict[str, PeerAgentBackend] = {
        "strix": StrixBackend(
            llm_provider=llm_provider,
            secret_lookup=secret_lookup,
        ),
    }

    if enable_shannon and shannon_repo_path is not None:
        registry.register(shannon_descriptor())
        backends["shannon"] = ShannonBackend(
            repo_path=shannon_repo_path,
            llm_key_name=shannon_llm_key_name,
            secret_lookup=secret_lookup,
        )

    if enable_ptai:
        registry.register(ptai_descriptor())
        backends["ptai"] = PtaiBackend(
            llm_provider=llm_provider,
            secret_lookup=secret_lookup,
            llm_key_name=ptai_llm_key_name,
        )

    if harness is None:
        harness = ContainerPeerAgentHarness(
            executor=SubprocessContainerExecutor(
                default_timeout=STRIX_DEFAULT_BUDGET.max_wall_seconds,
            ),
            backends=backends,
            workdir_root=workdir_root,
        )
    return PeerAgentService(
        registry=registry,
        harness=harness,
        audit=audit,
        runs=runs,
    )
