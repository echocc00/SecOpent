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
    # P2: "strix": ImageRef("usestrix/strix", "<tag>", ""),
    # P3: "shannon": ImageRef("keygraph/shannon", "<tag>", ""),
}
