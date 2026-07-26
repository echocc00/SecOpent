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
    "subfinder": ImageRef("projectdiscovery/subfinder", "latest", "sha256:8953620e5248c43871c7d852bf60095f326622c99e88e7ca831c201e68020a22"),
    "httpx": ImageRef("projectdiscovery/httpx", "latest", "sha256:e2f89a700e535b3e0d5ccf95e3383ebb54c2faecd8e8100573455cd0cbe8e02d"),
    "naabu": ImageRef("projectdiscovery/naabu", "latest", "sha256:0b7efcd6eb4bf7be2c5cfb2bbfe091a132df0e442e549267bca818a4cef15ea4"),
    "katana": ImageRef("projectdiscovery/katana", "latest", "sha256:a05d8460d34d06addc259da2543e554ef85ea756ed68e57701850fe09f326eff"),
    "fingerprinthub": ImageRef("dominicbreuker/fingerprintx", "latest", ""),  # digest TBD when pulled (A2)
    # --- Web/API (Task 10) ---
    "nuclei": ImageRef("projectdiscovery/nuclei", "latest", "sha256:e677842fb1f50f29747565ba274a1d35dcf8c684132a42b0cb406e71fccae9fc"),
    "dalfox": ImageRef("hahwul/dalfox", "latest", "sha256:91d5cebda9114fb7c2bfc7ad179ac5d605705c0bf4632a68f572f7a2f1d8a6dc"),
    "restler": ImageRef("mcr.microsoft.com/restlerfuzzer/restler", "latest", ""),  # digest TBD (A2)
    "schemathesis": ImageRef("schemathesis/schemathesis", "latest", ""),  # digest TBD (A2)
    "zap": ImageRef("owasp/zap2docker-stable", "latest", ""),  # digest TBD (A2, Standalone-only)
    # --- Network host (Task 11) ---
    "nmap": ImageRef("instrumentisto/nmap", "latest", "sha256:96f6ed194519b62421a1a1c57809e65a7f94d2aa1c8c25676f247e5e148c0827"),
    "nuclei_tcp": ImageRef("projectdiscovery/nuclei", "latest", "sha256:e677842fb1f50f29747565ba274a1d35dcf8c684132a42b0cb406e71fccae9fc"),  # same image, TCP templates
    # --- Cloud container (Task 12) ---
    "prowler": ImageRef("toniblyx/prowler", "latest", ""),  # digest TBD (A2)
    "trivy": ImageRef("aquasec/trivy", "latest", ""),  # digest TBD (A2)
    "kube_bench": ImageRef("aquasec/kube-bench", "latest", ""),  # digest TBD (A2)
    "checkov": ImageRef("bridgecrew/checkov", "latest", ""),  # digest TBD (A2)
    "scoutsuite": ImageRef("yelp/yesod", "latest", ""),  # digest TBD (A2, placeholder - verify image name)
    # --- Targets (E2E) ---
    "juice_shop": ImageRef("bkimminich/juice-shop", "latest", "sha256:e68144772ebaaca0ec117b38d44903af92416793230288ef7c5437fc4f26850a"),
    "httpbin": ImageRef("kennethreitz/httpbin", "latest", "sha256:599fe5e5073102dbb0ee3dbb65f049dab44fa9fc251f6835c9990f8fb196a72b"),
    # crAPI is multi-image (web+api+auth+db), started via docker-compose, not in catalog
    # --- Infrastructure ---
    "interactsh_server": ImageRef("projectdiscovery/interactsh-server", "latest", "sha256:f75d1fdeb0598012ce4560158232a9ad99701da28b31c141dc95d03402e4aa4f"),
    "alpine": ImageRef("library/alpine", "latest", "sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"),
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
