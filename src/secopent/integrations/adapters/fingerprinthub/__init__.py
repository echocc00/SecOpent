"""FingerprintHub adapter: web fingerprint matching (passive, §8.2).

FingerprintHub is the fingerprint module bundled with the ProjectDiscovery
httpx / nuclei ecosystem. It identifies web applications and components by
matching response features (headers, body, favicon) against a curated rule
set. Each match is surfaced as an Observation with `coverage_domain=asset`
and (where the rule carries a known CWE/OWASP mapping) populated `cwe` /
`owasp` tuples so CoverageMatrix can credit the relevant test class.
"""
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

_PARSER_ENTRYPOINT = "secopent_adapters.fingerprinthub:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "1.9.0"

# Mapping of common fingerprint rule tags to OWASP top-10 references. Empty
# tuples mean the fingerprint is purely informational (most are). This is a
# curated subset; M2 may swap it for a config-driven mapping.
_TAG_OWASP: dict[str, tuple[str, ...]] = {
    "wordpress": ("A01",),  # broken access control surface area
    "phpmyadmin": ("A01", "A07"),  # auth + identification failures
    "jenkins": ("A05",),  # security misconfiguration
    "git": ("A05",),  # sensitive data exposure via .git
}


def manifest() -> AdapterManifest:
    _image = IMAGE_CATALOG.get("fingerprinthub")
    _digest = (
        _image.digest if _image and _image.digest
        else "sha256:fingerprinthub-" + _UPSTREAM_VERSION
    )
    return AdapterManifest(
        id="fingerprinthub",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="MIT",
        upstream=AdapterUpstream(
            name="FingerprintHub",
            url="https://github.com/StarCrossPortal/FingerprintHub",
            version=_UPSTREAM_VERSION,
            digest=_digest,
        ),
        risk_class=RiskClass.PASSIVE,
        coverage_domain=(CoverageDomain.ASSET,),
        input_schema="schema://fingerprinthub/input.json",
        output_schema="schema://fingerprinthub/output.json",
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
    """Parse FingerprintHub JSONL stdout into Observation records.

    Each record carries at minimum `url` and a `fingerprints` list (or a
    single `fingerprint` string). Where the fingerprint name maps to a known
    OWASP reference, the Observation's `owasp` tuple is populated.
    """
    records = safe_jsonl_load(stdout)
    if not records:
        return ()
    observations: list[Observation] = []
    seen: set[tuple[str, str]] = set()
    for idx, record in enumerate(records):
        url = record.get("url") or record.get("host") or record.get("input")
        if not url:
            continue
        fingerprints = record.get("fingerprints")
        if not fingerprints:
            single = record.get("fingerprint")
            fingerprints = [single] if single else []
        if not fingerprints:
            continue
        for fp in fingerprints:
            if not isinstance(fp, str):
                continue
            key = (url, fp)
            if key in seen:
                continue
            seen.add(key)
            fp_lower = fp.lower()
            owasp = _TAG_OWASP.get(fp_lower, ())
            observations.append(
                Observation(
                    external_id=f"fingerprinthub:{url}:{fp}:{idx}",
                    asset_identity=url,
                    source=source,
                    rule_id="fingerprinthub.match",
                    rule_version=_UPSTREAM_VERSION,
                    coverage_domain=CoverageDomain.ASSET,
                    title=f"fingerprint: {fp} on {url}",
                    severity=Severity.INFO,
                    confidence=0.85,
                    cwe=(),
                    cve=(),
                    owasp=owasp,
                    raw={"url": url, "fingerprint": fp, **dict(record)},
                )
            )
    return tuple(observations)
