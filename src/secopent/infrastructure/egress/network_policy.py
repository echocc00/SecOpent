# src/secopent/infrastructure/egress/network_policy.py
"""Network policy for tool containers (Phase A Task A2, option c).

Defines the network modes a tool container runs under. **option c** is the V1
choice:

- Containers run on the Docker **bridge** network (Docker Desktop's default;
  ``--network=host`` does NOT take effect on Docker Desktop for Windows/Mac).
- Containers reach target ranges running on the host via
  ``host.docker.internal`` (e.g. ``http://host.docker.internal:3000`` for
  Juice Shop), NOT ``localhost`` (which is the container itself).
- **Scope is enforced at the application layer** by ``PolicyEngine.evaluate``
  (M0) and ``ScopeEnforcer``/``EgressGuard`` (M5) - the AdapterRunner refuses
  out-of-scope targets before any container runs, and the egress guard blocks
  cloud-metadata / loopback / DB / Docker-host destinations.

M5 strengthens this to real **network-layer isolation** (nftables/netns) that
blocks metadata/DB/Docker-host at the packet level regardless of application
logic. Until then, the bridge network relies on Docker's default behaviour of
not routing link-local (169.254.0.0/16), plus the application-layer guards.
"""
from __future__ import annotations

from enum import StrEnum

# Docker host gateway hostname (Docker Desktop) for reaching host-side targets.
HOST_GATEWAY = "host.docker.internal"


class NetworkPolicy(StrEnum):
    """Network modes for tool containers."""

    # option c: Docker bridge + host.docker.internal + app-layer scope.
    BRIDGE = "bridge"
    # The §8.4 name carried by AdapterManifest.network_policy; mapped to BRIDGE
    # under option c (real scoped egress via nftables lands in M5).
    SCOPED_EGRESS = "scoped-egress"


# The default network mode applied by the executor under option c.
DEFAULT_NETWORK_MODE = "bridge"


def resolve_network_mode(policy: str) -> str:
    """Map a manifest network policy to the docker network mode (option c).

    Both ``bridge`` and ``scoped-egress`` map to the bridge network in V1;
    scope enforcement is application-layer (PolicyEngine/ScopeEnforcer) until
    M5 adds nftables/netns isolation.
    """
    return DEFAULT_NETWORK_MODE
