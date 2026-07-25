"""httpx adapter: HTTP probe + tech detection (passive/low, §8.2)."""
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
from secopent.integrations.adapters._common import safe_jsonl_load

_PARSER_ENTRYPOINT = "secopent_adapters.httpx:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "1.6.9"


def manifest() -> AdapterManifest:
    return AdapterManifest(
        id="httpx",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="MIT",
        upstream=AdapterUpstream(
            name="httpx",
            url="https://github.com/projectdiscovery/httpx",
            version=_UPSTREAM_VERSION,
            digest="sha256:httpx-" + _UPSTREAM_VERSION,
        ),
        risk_class=RiskClass.PASSIVE,
        coverage_domain=(CoverageDomain.ASSET,),
        input_schema="schema://httpx/input.json",
        output_schema="schema://httpx/output.json",
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
    """Parse httpx JSONL stdout into Observation records.

    httpx emits one JSON object per probed URL with fields like `url`,
    `status_code`, `title`, `tech` (or `technologies`), `webserver`.
    Each live host becomes one Observation with `asset_identity=url`.
    """
    records = safe_jsonl_load(stdout)
    if not records:
        return ()
    observations: list[Observation] = []
    seen: set[str] = set()
    for idx, record in enumerate(records):
        url = record.get("url") or record.get("input")
        if not url or url in seen:
            continue
        seen.add(url)
        tech = record.get("tech") or record.get("technologies") or []
        status_code = record.get("status_code")
        title = record.get("title", "")
        raw = dict(record)
        raw.setdefault("tech", list(tech) if isinstance(tech, list | tuple) else [tech])
        observations.append(
            Observation(
                external_id=f"httpx:{url}:{idx}",
                asset_identity=url,
                source=source,
                rule_id="httpx.probe",
                rule_version=_UPSTREAM_VERSION,
                coverage_domain=CoverageDomain.ASSET,
                title=f"http probe: {url} status={status_code} title={title!r}",
                severity=Severity.INFO,
                confidence=0.95,
                cwe=(),
                cve=(),
                owasp=(),
                raw=raw,
            )
        )
    return tuple(observations)
