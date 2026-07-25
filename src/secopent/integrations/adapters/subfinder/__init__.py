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
from secopent.integrations.adapters._common import safe_jsonl_load

_PARSER_ENTRYPOINT = "secopent_adapters.subfinder:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "2.6.7"


def manifest() -> AdapterManifest:
    """Return the subfinder AdapterManifest.

    subfinder is a passive subdomain enumeration tool (ProjectDiscovery, MIT).
    Upstream digest is a placeholder sha256 - the real digest is pinned at M5
    container build time; for M1 the manifest only needs to be structurally
    valid and uniquely identifiable.
    """
    return AdapterManifest(
        id="subfinder",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="MIT",
        upstream=AdapterUpstream(
            name="subfinder",
            url="https://github.com/projectdiscovery/subfinder",
            version=_UPSTREAM_VERSION,
            digest="sha256:subfinder-" + _UPSTREAM_VERSION,
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
