# src/secopent/interfaces/api/routers/tools.py
"""Tools resource router (Phase A P1, W1): the adapter/tool registry.

Lists the available tool adapters from the IMAGE_CATALOG (the digest-pinned
tool images). No database needed - the catalog is the source of truth. The Web
UI uses this to show selectable tools per coverage domain.
"""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from ....infrastructure.adapters.image_catalog import IMAGE_CATALOG

router = APIRouter(prefix="/tools", tags=["tools"])

# adapter key -> coverage domain, for the Web UI to group tools.
_ADAPTER_DOMAIN = {
    "subfinder": "asset",
    "httpx": "asset",
    "naabu": "asset",
    "katana": "asset",
    "fingerprinthub": "asset",
    "nuclei": "web",
    "dalfox": "web",
    "restler": "web",
    "schemathesis": "web",
    "zap": "web",
    "nmap": "network",
    "nuclei_tcp": "network",
    "prowler": "cloud",
    "trivy": "cloud",
    "kube_bench": "cloud",
    "checkov": "cloud",
    "scoutsuite": "cloud",
}


class ToolOut(BaseModel):
    key: str
    image: str
    tag: str
    digest: str
    domain: str


@router.get("", response_model=list[ToolOut])
def list_tools() -> list[ToolOut]:
    tools: list[ToolOut] = []
    for key, ref in IMAGE_CATALOG.items():
        if key in _ADAPTER_DOMAIN:
            tools.append(
                ToolOut(
                    key=key,
                    image=ref.name,
                    tag=ref.tag,
                    digest=ref.digest,
                    domain=_ADAPTER_DOMAIN[key],
                )
            )
    return tools
