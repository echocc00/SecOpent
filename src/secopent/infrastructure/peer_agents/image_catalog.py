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
    # Digest pinned after first build; verify with `docker images --digests`.
    "strix": ImageRef("secopent/peer-worker-strix", "1.4.1", ""),
    # P3: "shannon": ImageRef("keygraph/shannon", "<tag>", ""),
}
