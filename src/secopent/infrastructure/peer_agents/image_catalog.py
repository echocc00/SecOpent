# src/secopent/infrastructure/peer_agents/image_catalog.py
"""Image catalog for peer agents (spec §5 P0; entries land with P2/P3).

Same digest-pinning policy as ``infrastructure/adapters/image_catalog.py``:
``docker pull <image>@<digest>``, record the digest here, upgrades require an
explicit catalog change + re-pin. P2 adds the Strix entry (plan #4), P3 the
Shannon entry (plan #6) - digests are filled after the first pull.
"""
from __future__ import annotations

from ..adapters.image_catalog import ImageRef

PEER_IMAGE_CATALOG: dict[str, ImageRef] = {
    # Locally built: `docker build -t secopent/peer-worker-strix:1.4.1 -f
    # worker_images/strix/Dockerfile worker_images/strix/`. Digest is the
    # local manifest-list digest (docker images --digests); pin it here so the
    # executor's digest check enforces the exact local build. Re-pin after any
    # rebuild or registry push (supply-chain §8.1).
    "strix": ImageRef(
        "secopent/peer-worker-strix",
        "1.4.1",
        "sha256:cdd9bac04730bd718a7cbddf68dd8d1a5f7ca7e0c10247f11fd6b61a666e2b71",
    ),
    # P3: Shannon (AGPL-3.0). Pulled from Docker Hub (keygraph/shannon);
    # ghcr.io/keygraph/shannon is denied. Digest pinned after first successful
    # pull (supply-chain §8.1). Shannon stays registered-behind-flag
    # (enable_shannon, default off); re-pin after upgrades.
    "shannon": ImageRef(
        "keygraph/shannon",
        "latest",
        "sha256:0d7d462981bdf7829099c363df827a6607426f765493c6ef2403602c7ed45b07",
    ),
    # Phase 2.10 (A4 spike): ptai (0xSteph, MIT) is an autonomous AI pentest
    # agent distributed as MCP server + CLI. Linux-only: impacket / bloodhound
    # / scapy / paramiko install cleanly only on Linux, so the peer-worker-ptai
    # image must be built on a Linux worker (the Windows dev environment cannot
    # `pip install ptai` with deps). digest="" until the first Linux build
    # records a manifest-list digest; the executor's digest check skips
    # tag-only refs (no `@`), so a locally-built image works until a registry
    # push pins it. Re-pin after upgrades.
    "ptai": ImageRef(
        "secopent/peer-worker-ptai",
        "1.1.0",
        "",
    ),
}
