"""naabu adapter: port scanning (low-risk active recon, §8.2)."""
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

_PARSER_ENTRYPOINT = "secopent_adapters.naabu:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "2.3.3"


def manifest() -> AdapterManifest:
    return AdapterManifest(
        id="naabu",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="MIT",
        upstream=AdapterUpstream(
            name="naabu",
            url="https://github.com/projectdiscovery/naabu",
            version=_UPSTREAM_VERSION,
            digest="sha256:naabu-" + _UPSTREAM_VERSION,
        ),
        risk_class=RiskClass.LOW,
        coverage_domain=(CoverageDomain.ASSET,),
        input_schema="schema://naabu/input.json",
        output_schema="schema://naabu/output.json",
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
    """Parse naabu JSONL stdout into Observation records.

    naabu emits one JSON object per open port:
        {"ip": "10.0.0.1", "port": 22, "host": "example.com"}
    `asset_identity` is `ip:port` (host appended when present).
    """
    records = safe_jsonl_load(stdout)
    if not records:
        return ()
    observations: list[Observation] = []
    seen: set[str] = set()
    for idx, record in enumerate(records):
        ip = record.get("ip") or record.get("host") or record.get("address")
        port = record.get("port")
        if not ip or port is None:
            continue
        asset_identity = f"{ip}:{port}"
        if asset_identity in seen:
            continue
        seen.add(asset_identity)
        observations.append(
            Observation(
                external_id=f"naabu:{asset_identity}:{idx}",
                asset_identity=asset_identity,
                source=source,
                rule_id="naabu.open_port",
                rule_version=_UPSTREAM_VERSION,
                coverage_domain=CoverageDomain.ASSET,
                title=f"open port: {asset_identity}",
                severity=Severity.INFO,
                confidence=0.95,
                cwe=(),
                cve=(),
                owasp=(),
                raw=dict(record),
            )
        )
    return tuple(observations)
