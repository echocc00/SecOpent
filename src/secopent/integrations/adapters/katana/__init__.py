"""katana adapter: crawler/spider (passive recon, §8.2)."""
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

_PARSER_ENTRYPOINT = "secopent_adapters.katana:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "1.1.0"


def manifest() -> AdapterManifest:
    _image = IMAGE_CATALOG.get("katana")
    _digest = _image.digest if _image and _image.digest else "sha256:katana-" + _UPSTREAM_VERSION
    return AdapterManifest(
        id="katana",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="MIT",
        upstream=AdapterUpstream(
            name="katana",
            url="https://github.com/projectdiscovery/katana",
            version=_UPSTREAM_VERSION,
            digest=_digest,
        ),
        risk_class=RiskClass.PASSIVE,
        coverage_domain=(CoverageDomain.ASSET,),
        input_schema="schema://katana/input.json",
        output_schema="schema://katana/output.json",
        network_policy="scoped-egress",
        parser=_PARSER_ENTRYPOINT,
        fixtures=(
            "fixtures/positive.json",
            "fixtures/negative.json",
            "fixtures/timeout.txt",
            "fixtures/malformed.json",
        ),
        permissions=("network.connect",),
    )


def parse(
    *, stdout: str, source: AdapterSource, artifacts: dict[str, bytes]
) -> tuple[Observation, ...]:
    """Parse katana JSONL stdout into Observation records.

    katana emits one JSON object per crawled URL:
        {"request": {"endpoint": "https://example.com/admin"}, "method": "GET", ...}
    Some versions emit a flat `{"url": "..."}` instead - we accept both.
    """
    records = safe_jsonl_load(stdout)
    if not records:
        return ()
    observations: list[Observation] = []
    seen: set[str] = set()
    for idx, record in enumerate(records):
        request = record.get("request")
        if isinstance(request, dict):
            url = request.get("endpoint") or request.get("url")
        else:
            url = record.get("url") or record.get("endpoint")
        if not url or url in seen:
            continue
        seen.add(url)
        observations.append(
            Observation(
                external_id=f"katana:{url}:{idx}",
                asset_identity=url,
                source=source,
                rule_id="katana.crawl",
                rule_version=_UPSTREAM_VERSION,
                coverage_domain=CoverageDomain.ASSET,
                title=f"crawled URL: {url}",
                severity=Severity.INFO,
                confidence=0.9,
                cwe=(),
                cve=(),
                owasp=(),
                raw=dict(record),
            )
        )
    return tuple(observations)
