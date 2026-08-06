"""nuclei_tcp adapter: nuclei TCP/dns/ssl template matches (§8.2, network).

This adapter is the network-host projection of nuclei. It runs nuclei with
a curated template set restricted to non-HTTP transports (TCP, dns, ssl,
network) and parses the JSONL output. Each finding becomes one
Observation whose `coverage_domain=network`, with CWE/CVE populated from
the template tags and references via the same curated map used by the
Web nuclei adapter (extended with network-transport-specific tags).

Parser input: nuclei JSONL stdout (`-j -t nuclei-templates/ -type tcp,dns,
ssl,network`). Output schema mirrors the Web nuclei adapter so downstream
CoverageMatrix/Finding correlation logic is shared.
"""
from __future__ import annotations

import re
from typing import Any

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

_PARSER_ENTRYPOINT = "secopent_adapters.nuclei_tcp:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "3.3.7"

# ---------------------------------------------------------------------------
# Curated template-tag -> (CWE, OWASP) map, focused on network-transport
# findings (TCP/dns/ssl/network). Keys are lower-case tag strings.
# Sources: OWASP Top 10 2021 + CWE-1000 view, mapped against the
# ProjectDiscovery nuclei-templates tag taxonomy for non-HTTP templates.
# ---------------------------------------------------------------------------
_TAG_MAP: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    # SSL/TLS family (OWASP A02:2021 Cryptographic Failures)
    "ssl": (("CWE-295",), ("A02:2021",)),
    "tls": (("CWE-295",), ("A02:2021",)),
    "heartbleed": (("CWE-319",), ("A02:2021",)),
    "poodle": (("CWE-327",), ("A02:2021",)),
    "cbc": (("CWE-327",), ("A02:2021",)),
    "weak-cipher": (("CWE-327",), ("A02:2021",)),
    "weak-crypto": (("CWE-327",), ("A02:2021",)),
    "mitm": (("CWE-295",), ("A02:2021",)),
    # DNS family
    "dns": (("CWE-200",), ("A05:2021",)),
    "zone-transfer": (("CWE-200",), ("A05:2021",)),
    "dnssec": (("CWE-345",), ("A05:2021",)),
    "subdomain-takeover": (("CWE-350",), ("A05:2021",)),
    "takeover": (("CWE-350",), ("A05:2021",)),
    # TCP / network service family
    "exposure": (("CWE-200",), ("A05:2021",)),
    "exposed-service": (("CWE-200",), ("A05:2021",)),
    "default-login": (("CWE-521",), ("A07:2021",)),
    "weak-password": (("CWE-521",), ("A07:2021",)),
    "rce": (("CWE-78",), ("A03:2021",)),
    # Banner / fingerprint
    "fingerprint": ((), ()),
    "tech": ((), ()),
}

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def manifest() -> AdapterManifest:
    """Return the nuclei_tcp AdapterManifest.

    nuclei is MIT-licensed and active (sends payloads). risk_class=ACTIVE.
    coverage_domain is the network domain only - this adapter runs nuclei
    with non-HTTP template types (TCP/dns/ssl/network). It is available in
    both Lite and Standalone profiles.
    """
    _image = IMAGE_CATALOG.get("nuclei_tcp")
    _digest = _image.digest if _image and _image.digest else "sha256:nuclei-" + _UPSTREAM_VERSION
    return AdapterManifest(
        id="nuclei_tcp",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="MIT",
        upstream=AdapterUpstream(
            name="nuclei",
            url="https://github.com/projectdiscovery/nuclei",
            version=_UPSTREAM_VERSION,
            digest=_digest,
        ),
        risk_class=RiskClass.ACTIVE,
        coverage_domain=(CoverageDomain.NETWORK,),
        input_schema="schema://nuclei_tcp/input.json",
        output_schema="schema://nuclei_tcp/output.jsonl",
        network_policy="scoped-egress",
        parser=_PARSER_ENTRYPOINT,
        fixtures=(
            "fixtures/positive.jsonl",
            "fixtures/negative.jsonl",
            "fixtures/timeout.txt",
            "fixtures/malformed.jsonl",
        ),
        permissions=("active", "network.connect"),
    )


def _map_tags(tags: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Map a nuclei tag list to (cwe, owasp) tuples via the curated map."""
    if not tags:
        return (), ()
    if isinstance(tags, str):
        tags = [tags]
    cwes: set[str] = set()
    owasps: set[str] = set()
    for tag in tags:
        if not isinstance(tag, str):
            continue
        cwe, owasp = _TAG_MAP.get(tag.lower(), ((), ()))
        cwes.update(cwe)
        owasps.update(owasp)
    return tuple(sorted(cwes)), tuple(sorted(owasps))


def _extract_cve(reference: Any) -> tuple[str, ...]:
    """Extract unique CVE IDs from a nuclei `reference` list or template-id."""
    cves: list[str] = []
    items: list[Any] = []
    if isinstance(reference, str):
        items = [reference]
    elif isinstance(reference, list):
        items = list(reference)
    for ref in items:
        if not isinstance(ref, str):
            continue
        for match in _CVE_RE.findall(ref):
            cves.append(match.upper())
    return tuple(dict.fromkeys(cves))


def parse(
    *, stdout: str, source: AdapterSource, artifacts: dict[str, bytes]
) -> tuple[Observation, ...]:
    """Parse nuclei TCP/dns/ssl JSONL stdout into Observation records.

    Each line is one finding:
        {
          "template-id": "ssl/heartbleed",
          "info": {"name": "SSL Heartbleed", "tags": ["ssl", "heartbleed"],
                   "severity": "high"},
          "matched-at": "10.0.0.1:443",
          "host": "10.0.0.1",
          "type": "ssl",
          "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"]
        }

    Each finding becomes one Observation with `coverage_domain=network`,
    CWE/OWASP populated from the template tags via `_TAG_MAP`, CVE
    extracted from references and (fallback) the template-id, severity
    from `info.severity`.
    """
    records = safe_jsonl_load(stdout)
    if not records:
        return ()
    observations: list[Observation] = []
    seen: set[str] = set()
    for idx, record in enumerate(records):
        info_val: Any = record.get("info")
        info: dict[str, Any] = info_val if isinstance(info_val, dict) else {}
        template_id = (
            record.get("template-id")
            or record.get("templateID")
            or record.get("template_id")
            or info.get("name")
            or f"unknown-{idx}"
        )
        host = (
            record.get("matched-at")
            or record.get("matched-host")
            or record.get("host")
            or record.get("ip")
            or ""
        )
        if not host or host in seen:
            continue
        seen.add(host)
        tags = info.get("tags") or record.get("tags") or []
        cwe, owasp = _map_tags(tags)
        cve = _extract_cve(record.get("reference") or info.get("reference"))
        if not cve and isinstance(template_id, str):
            cve = _extract_cve([template_id])
        sev_str = str(info.get("severity", "info")).lower()
        severity = _SEVERITY_MAP.get(sev_str, Severity.INFO)
        title = str(info.get("name") or template_id)
        raw = dict(record)
        raw.setdefault("template-id", template_id)
        raw_tags: list[Any] = list(tags) if isinstance(tags, list) else [tags]
        raw.setdefault("tags", raw_tags)
        observations.append(
            Observation(
                external_id=f"nuclei_tcp:{template_id}:{host}:{idx}",
                asset_identity=host,
                source=source,
                rule_id=str(template_id),
                rule_version=_UPSTREAM_VERSION,
                coverage_domain=CoverageDomain.NETWORK,
                title=title,
                severity=severity,
                confidence=0.9,
                cwe=cwe,
                cve=cve,
                owasp=owasp,
                raw=raw,
            )
        )
    return tuple(observations)
