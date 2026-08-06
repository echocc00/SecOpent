"""subfinder adapter: subdomain enumeration (passive recon, §8.2)."""
from __future__ import annotations

from secopent.domain.adapters.contracts import (
    AdapterManifest,
    AdapterSource,
    AdapterUpstream,
    CoverageDomain,
    Observation,
    Severity,
)
from secopent.domain.policy.models import RiskClass
from secopent.infrastructure.adapters.image_catalog import IMAGE_CATALOG
from secopent.integrations.adapters._common import safe_jsonl_load

_PARSER_ENTRYPOINT = "secopent_adapters.subfinder:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "2.6.7"


def manifest() -> AdapterManifest:
    """Return the subfinder AdapterManifest.

    subfinder is a passive subdomain enumeration tool (ProjectDiscovery, MIT).

    The upstream ``digest`` is read dynamically from ``image_catalog`` (the
    single source of truth for pinned image digests, §8.1 supply-chain gate).
    If the catalog digest is empty (image pull pending/failed), the manifest
    falls back to the ``sha256:subfinder-<version>`` placeholder - structurally
    valid + uniquely identifiable, but NOT a real image content hash; the
    AdapterRunner will refuse to launch it once a real digest is required.
    """
    _image = IMAGE_CATALOG.get("subfinder")
    _digest = _image.digest if _image and _image.digest else "sha256:subfinder-" + _UPSTREAM_VERSION
    return AdapterManifest(
        id="subfinder",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="MIT",
        upstream=AdapterUpstream(
            name="subfinder",
            url="https://github.com/projectdiscovery/subfinder",
            version=_UPSTREAM_VERSION,
            digest=_digest,
        ),
        risk_class=RiskClass.PASSIVE,
        coverage_domain=(CoverageDomain.ASSET,),
        input_schema="schema://subfinder/input.json",
        output_schema="schema://subfinder/output.json",
        network_policy="scoped-egress",
        parser=_PARSER_ENTRYPOINT,
        fixtures=(
            "fixtures/positive.json",
            "fixtures/negative.json",
            "fixtures/timeout.txt",
            "fixtures/malformed.json",
        ),
        permissions=("passive",),
    )


def parse(
    *, stdout: str, source: AdapterSource, artifacts: dict[str, bytes]
) -> tuple[Observation, ...]:
    """Parse subfinder JSONL stdout into Observation records.

    subfinder emits one JSON object per line per discovered subdomain:
        {"host": "www.example.com", "source": "crtsh", ...}

    Each discovered host becomes one Observation with
    `coverage_domain=asset`, `asset_identity=host`, `severity=info`.
    """
    records = safe_jsonl_load(stdout)
    if not records:
        return ()
    observations: list[Observation] = []
    seen: set[str] = set()
    for idx, record in enumerate(records):
        host = record.get("host") or record.get("domain")
        if not host or host in seen:
            continue
        seen.add(host)
        observations.append(
            Observation(
                external_id=f"subfinder:{host}:{idx}",
                asset_identity=host,
                source=source,
                rule_id="subfinder.subdomain",
                rule_version=_UPSTREAM_VERSION,
                coverage_domain=CoverageDomain.ASSET,
                title=f"subdomain discovered: {host}",
                severity=Severity.INFO,
                confidence=0.9,
                cwe=(),
                cve=(),
                owasp=(),
                raw=dict(record),
            )
        )
    return tuple(observations)
