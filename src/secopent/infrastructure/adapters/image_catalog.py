"""Image catalog for SecOpent adapters (Phase A Task A1).

Pins each adapter's upstream image to a sha256 digest for supply-chain safety
(§8.1 - digest 固定). Digests are filled in after pulling; the catalog is the
single source of truth for which image+digest each adapter runs.

Pull policy: `docker pull <image>@<digest>` (digest-pinned). If an image has
no stable digest (rolling `:latest`), we record the digest at pull time and
pin it here; upgrades require an explicit catalog change + re-pin.

Images are pulled via China registry mirrors (docker.1panel.live /
docker.m.daocloud.io) configured in Docker Desktop daemon.json, but the
catalog stores the canonical docker.io names - mirrors are transparent.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ImageRef:
    """A digest-pinned image reference."""

    name: str  # canonical docker.io name, e.g. "projectdiscovery/nuclei"
    tag: str  # e.g. "latest" or "v3.11.0"
    digest: str  # "sha256:..." - empty string until pinned


# 17 adapters (§8.2) + targets + infrastructure images.
# Digests filled after first pull; verify with `docker images --digests`.
IMAGE_CATALOG: dict[str, ImageRef] = {
    # --- Asset mapping (Task 9) ---
    "subfinder": ImageRef("projectdiscovery/subfinder", "latest", ""),
    "httpx": ImageRef("projectdiscovery/httpx", "latest", ""),
    "naabu": ImageRef("projectdiscovery/naabu", "latest", ""),
    "katana": ImageRef("projectdiscovery/katana", "latest", ""),
    "fingerprinthub": ImageRef("dominicbreuker/fingerprintx", "latest", ""),
    # --- Web/API (Task 10) ---
    "nuclei": ImageRef("projectdiscovery/nuclei", "latest", ""),
    "dalfox": ImageRef("hahwul/dalfox", "latest", ""),
    "restler": ImageRef("mcr.microsoft.com/restlerfuzzer/restler", "latest", ""),
    "schemathesis": ImageRef("schemathesis/schemathesis", "latest", ""),
    "zap": ImageRef("owasp/zap2docker-stable", "latest", ""),
    # --- Network host (Task 11) ---
    "nmap": ImageRef("instrumentisto/nmap", "latest", ""),
    "nuclei_tcp": ImageRef("projectdiscovery/nuclei", "latest", ""),  # same image, TCP templates
    # --- Cloud container (Task 12) ---
    "prowler": ImageRef("toniblyx/prowler", "latest", ""),
    "trivy": ImageRef("aquasec/trivy", "latest", ""),
    "kube_bench": ImageRef("aquasec/kube-bench", "latest", ""),
    "checkov": ImageRef("bridgecrew/checkov", "latest", ""),
    "scoutsuite": ImageRef("yelp/yesod", "latest", ""),  # ScoutSuite image (placeholder, verify)
    # --- Targets (E2E) ---
    "juice_shop": ImageRef("bkimminich/juice-shop", "latest", ""),
    "httpbin": ImageRef("kennethreitz/httpbin", "latest", ""),
    # crAPI is multi-image (web+api+auth+db), started via docker-compose, not in catalog
    # --- Infrastructure ---
    "interactsh_server": ImageRef("projectdiscovery/interactsh-server", "latest", ""),
    "alpine": ImageRef("library/alpine", "latest", ""),
}


def ref(adapter_key: str) -> ImageRef:
    """Return the digest-pinned ImageRef for an adapter key."""
    return IMAGE_CATALOG[adapter_key]


def pull_spec(adapter_key: str) -> str:
    """Return the `docker pull` argument: `name:tag` (mirror-transparent).

    Digest-pinned pulls use `name@digest` once digests are filled in.
    """
    image = ref(adapter_key)
    return f"{image.name}:{image.tag}" if not image.digest else f"{image.name}@{image.digest}"
