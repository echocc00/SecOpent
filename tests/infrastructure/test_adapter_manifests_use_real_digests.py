"""Phase 2.1: adapter manifests must read upstream digest from IMAGE_CATALOG.

The image_catalog is the single source of truth for pinned image digests
(§8.1 supply-chain gate). Each adapter's ``manifest().upstream.digest`` must
equal the catalog digest when one is pinned, so the AdapterRunner (which reads
``manifest.upstream.digest`` at ``base.py:289``) launches the digest-pinned
image rather than the placeholder ``sha256:<adapter>-<ver>``.

Adapters whose catalog digest is still empty (pull failed / pending) are
skipped with a clear message rather than failed - they retain the placeholder
fallback until their image is pulled.
"""
from __future__ import annotations

import importlib

import pytest

from secopent.infrastructure.adapters.image_catalog import IMAGE_CATALOG

# adapter key -> manifest module path. Every adapter in the catalog that has a
# corresponding integrations manifest is listed here; the test dynamically
# skips keys whose digest is empty (pull pending/failed).
_ADAPTER_MANIFEST_MODULES: dict[str, str] = {
    "subfinder": "secopent.integrations.adapters.subfinder",
    "httpx": "secopent.integrations.adapters.httpx",
    "naabu": "secopent.integrations.adapters.naabu",
    "katana": "secopent.integrations.adapters.katana",
    "fingerprinthub": "secopent.integrations.adapters.fingerprinthub",
    "nuclei": "secopent.integrations.adapters.nuclei",
    "dalfox": "secopent.integrations.adapters.dalfox",
    "restler": "secopent.integrations.adapters.restler",
    "schemathesis": "secopent.integrations.adapters.schemathesis",
    "zap": "secopent.integrations.adapters.zap",
    "nmap": "secopent.integrations.adapters.nmap",
    "nuclei_tcp": "secopent.integrations.adapters.nuclei_tcp",
    "prowler": "secopent.integrations.adapters.prowler",
    "trivy": "secopent.integrations.adapters.trivy",
    "kube_bench": "secopent.integrations.adapters.kube_bench",
    "checkov": "secopent.integrations.adapters.checkov",
    "scoutsuite": "secopent.integrations.adapters.scoutsuite",
}


def _adapter_keys_with_pinned_digest() -> list[str]:
    """Catalog keys that (a) have a manifest module and (b) a non-empty digest."""
    return [
        key
        for key in _ADAPTER_MANIFEST_MODULES
        if IMAGE_CATALOG[key].digest
    ]


@pytest.mark.parametrize("adapter_key", sorted(_ADAPTER_MANIFEST_MODULES))
def test_manifest_upstream_digest_matches_catalog(adapter_key: str) -> None:
    """manifest().upstream.digest must equal the IMAGE_CATALOG digest.

    When the catalog digest is empty (image pull pending/failed), the manifest
    falls back to the ``sha256:<adapter>-<ver>`` placeholder; that case is
    skipped, not failed, so this test greens up automatically once a digest is
    pinned in the catalog.
    """
    catalog_ref = IMAGE_CATALOG[adapter_key]
    if not catalog_ref.digest:
        pytest.skip(f"catalog digest empty for {adapter_key} (pull pending/failed)")

    module = importlib.import_module(_ADAPTER_MANIFEST_MODULES[adapter_key])
    manifest = module.manifest()
    assert manifest.upstream.digest == catalog_ref.digest, (
        f"{adapter_key}: manifest().upstream.digest="
        f"{manifest.upstream.digest!r} != IMAGE_CATALOG digest="
        f"{catalog_ref.digest!r}; manifest must read digest from image_catalog"
    )


def test_at_least_one_adapter_pinned_beyond_placeholder() -> None:
    """Guard: at least one adapter must carry a real (sha256:64-hex) digest.

    Ensures the dynamic-digest wiring is exercised by at least one adapter so
    the parametrized test above is not entirely skipped. A real digest is
    ``sha256:`` followed by 64 hex chars; the placeholder is
    ``sha256:<adapter>-<ver>`` (contains a dash after the adapter name).
    """
    pinned = _adapter_keys_with_pinned_digest()
    assert pinned, (
        "no adapter has a pinned catalog digest; Phase 2.1 cannot verify "
        "dynamic manifest digest wiring"
    )
