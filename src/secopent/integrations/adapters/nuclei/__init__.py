"""nuclei adapter: template-driven Web vuln scanner (§8.2, active).

nuclei emits JSONL findings keyed by `template-id`. Each template carries a
list of `tags` (e.g. `sqli`, `xss`, `ssrf`, `cve`, `rce`) that map to CWE
and OWASP Top-10 categories. This curated map feeds the CoverageMatrix so
that a nuclei finding auto-satisfies the corresponding OWASP WSTG coverage
item.

The map below is intentionally small and curated - it covers the tags most
commonly seen across the public nuclei-templates repo for the OWASP Top-10
classes. Unknown tags fall back to an empty CWE/OWASP tuple (the finding
still surfaces as an Observation, just without coverage attribution).
"""
from __future__ import annotations

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
from secopent.integrations.adapters._common import safe_jsonl_load

_PARSER_ENTRYPOINT = "secopent_adapters.nuclei:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "3.3.7"

# ---------------------------------------------------------------------------
# Curated template-tag -> (CWE, OWASP) map.
# Keys are lower-case tag strings. Values are (cwe_tuple, owasp_tuple).
# Sources: OWASP Top 10 2021 + CWE-1000 view, mapped against the
# ProjectDiscovery nuclei-templates tag taxonomy.
# ---------------------------------------------------------------------------
_TAG_MAP: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    # Injection family (OWASP A03:2021 Injection)
    "sqli": (("CWE-89",), ("A03:2021",)),
    "sql-injection": (("CWE-89",), ("A03:2021",)),
    "xss": (("CWE-79",), ("A03:2021",)),
    "stored-xss": (("CWE-79",), ("A03:2021",)),
    "reflected-xss": (("CWE-79",), ("A03:2021",)),
    "dom-xss": (("CWE-79",), ("A03:2021",)),
    "ssrf": (("CWE-918",), ("A10:2021",)),
    "rce": (("CWE-78",), ("A03:2021",)),
    "lfi": (("CWE-22",), ("A01:2021",)),
    "rfi": (("CWE-98",), ("A03:2021",)),
    "command-injection": (("CWE-78",), ("A03:2021",)),
    "ssti": (("CWE-94",), ("A03:2021",)),
    # Auth & session (OWASP A07:2021)
    "default-login": (("CWE-521",), ("A07:2021",)),
    "weak-password": (("CWE-521",), ("A07:2021",)),
    "auth-bypass": (("CWE-287",), ("A07:2021",)),
    # Misconfig (OWASP A05:2021)
    "exposure": (("CWE-200",), ("A05:2021",)),
    "exposed-panel": (("CWE-200",), ("A05:2021",)),
    "misconfig": (("CWE-16",), ("A05:2021",)),
    # Crypto (OWASP A02:2021)
    "ssl": (("CWE-295",), ("A02:2021",)),
    "tls": (("CWE-295",), ("A02:2021",)),
    # Access control (OWASP A01:2021)
    "idor": (("CWE-639",), ("A01:2021",)),
    "authz": (("CWE-862",), ("A01:2021",)),
    # SSRF/redirect
    "open-redirect": (("CWE-601",), ("A01:2021",)),
}

# Severity string -> Severity enum. nuclei emits "critical"/"high"/"medium"/
# "low"/"info"; we lowercase and map.
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


def tag_coverage_map() -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:
    """Public view of the curated nuclei template-tag -> (CWE, OWASP) map.

    Consumed by the knowledge-layer curation-lag checker (P3 §3.4) to decide
    which upstream nuclei tags already map onto curated TestCatalog coverage.
    Returns a copy so callers cannot mutate the module's curated table.
    """
    return dict(_TAG_MAP)


def manifest() -> AdapterManifest:
    """Return the nuclei AdapterManifest.

    nuclei is an active scanner (sends payloads); risk_class=ACTIVE. It is
    available in both Lite and Standalone profiles (no standalone-only mark).
    """
    return AdapterManifest(
        id="nuclei",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="MIT",
        upstream=AdapterUpstream(
            name="nuclei",
            url="https://github.com/projectdiscovery/nuclei",
            version=_UPSTREAM_VERSION,
            digest="sha256:nuclei-" + _UPSTREAM_VERSION,
        ),
        risk_class=RiskClass.ACTIVE,
        coverage_domain=(CoverageDomain.WEB,),
        input_schema="schema://nuclei/input.json",
        output_schema="schema://nuclei/output.json",
        network_policy="scoped-egress",
        parser=_PARSER_ENTRYPOINT,
        fixtures=(
            "fixtures/positive.jsonl",
            "fixtures/negative.jsonl",
            "fixtures/timeout.txt",
            "fixtures/malformed.jsonl",
        ),
        permissions=("active",),
    )


def _map_tags(tags: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Map a nuclei tag list to (cwe, owasp) tuples via the curated map.

    Aggregates across all tags; unknown tags contribute nothing.
    """
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
    """Extract CVE IDs from a nuclei `reference` list (URLs or CVE strings)."""
    if not reference:
        return ()
    if isinstance(reference, str):
        reference = [reference]
    cves: list[str] = []
    for ref in reference:
        if not isinstance(ref, str):
            continue
        # Match CVE-YYYY-NNNNN... patterns.
        import re

        for match in re.findall(r"CVE-\d{4}-\d{4,7}", ref, flags=re.IGNORECASE):
            cves.append(match.upper())
    return tuple(dict.fromkeys(cves))  # dedupe, preserve order


def parse(
    *, stdout: str, source: AdapterSource, artifacts: dict[str, bytes]
) -> tuple[Observation, ...]:
    """Parse nuclei JSONL stdout into Observation records.

    Each line is one finding:
        {
          "template-id": "CVE-2021-44228",
          "info": {"name": "...", "tags": ["cve", "rce", "log4j"], "severity": "critical"},
          "matched-at": "https://example.com/",
          "host": "example.com",
          "matched-host": "https://example.com/",
          "type": "http",
          "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
        }

    Each finding becomes one Observation with `coverage_domain=web`, CWE/OWASP
    populated from the template tags via `_TAG_MAP`, CVE extracted from
    references, and severity from `info.severity`.
    """
    records = safe_jsonl_load(stdout)
    if not records:
        return ()
    observations: list[Observation] = []
    seen: set[str] = set()
    for idx, record in enumerate(records):
        info_raw = record.get("info")
        info: dict[str, Any] = info_raw if isinstance(info_raw, dict) else {}
        template_id = (
            record.get("template-id")
            or record.get("templateID")
            or record.get("template_id")
            or info.get("name")
            or f"unknown-{idx}"
        )
        host = (
            record.get("matched-host")
            or record.get("matched-at")
            or record.get("host")
            or record.get("url")
            or ""
        )
        # De-dupe on (template_id, matched target): real scans of one target
        # emit many findings that share a host, and distinct templates can match
        # the same URL - keying on host alone would drop distinct vulnerabilities.
        dedup_key = f"{template_id}|{host}"
        if not host or dedup_key in seen:
            continue
        seen.add(dedup_key)
        tags = info.get("tags") or record.get("tags") or []
        cwe, owasp = _map_tags(tags)
        cve = _extract_cve(record.get("reference") or info.get("reference"))
        # Also fold a CVE in the template-id itself (e.g. CVE-2021-44228).
        if not cve and isinstance(template_id, str):
            cve = _extract_cve([template_id])
        sev_str = str(info.get("severity", "info")).lower()
        severity = _SEVERITY_MAP.get(sev_str, Severity.INFO)
        title = str(info.get("name") or template_id)
        raw = dict(record)
        # Normalize raw so downstream always sees template-id/tags keys.
        raw.setdefault("template-id", template_id)
        raw.setdefault("tags", list(tags) if isinstance(tags, list) else [tags])
        observations.append(
            Observation(
                external_id=f"nuclei:{template_id}:{host}:{idx}",
                asset_identity=host,
                source=source,
                rule_id=str(template_id),
                rule_version=_UPSTREAM_VERSION,
                coverage_domain=CoverageDomain.WEB,
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
