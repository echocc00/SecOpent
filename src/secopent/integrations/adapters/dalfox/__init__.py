"""dalfox adapter: XSS specialist (§8.2, active).

dalfox emits JSON output (one JSON object per finding when run with
`--json`/`-f json`). Each finding represents a confirmed or suspected XSS
vector. The parser maps every finding to CWE-79 and OWASP A03:2021
(Injection) so the CoverageMatrix scores the XSS coverage item.
"""
from __future__ import annotations

import json
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

_PARSER_ENTRYPOINT = "secopent_adapters.dalfox:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "2.9.2"

# dalfox reports severity as one of: info/low/medium/high/critical.
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def manifest() -> AdapterManifest:
    """Return the dalfox AdapterManifest (active, XSS specialist)."""
    _image = IMAGE_CATALOG.get("dalfox")
    _digest = _image.digest if _image and _image.digest else "sha256:dalfox-" + _UPSTREAM_VERSION
    return AdapterManifest(
        id="dalfox",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="MIT",
        upstream=AdapterUpstream(
            name="dalfox",
            url="https://github.com/hahwul/dalfox",
            version=_UPSTREAM_VERSION,
            digest=_digest,
        ),
        risk_class=RiskClass.ACTIVE,
        coverage_domain=(CoverageDomain.WEB,),
        input_schema="schema://dalfox/input.json",
        output_schema="schema://dalfox/output.json",
        network_policy="scoped-egress",
        parser=_PARSER_ENTRYPOINT,
        fixtures=(
            "fixtures/positive.json",
            "fixtures/negative.json",
            "fixtures/timeout.txt",
            "fixtures/malformed.json",
        ),
        permissions=("active",),
    )


def _load_json_records(stdout: str) -> list[dict[str, Any]]:
    """Parse dalfox JSON output.

    dalfox may emit either a JSON array of findings or newline-delimited
    JSON objects. Non-JSON lines (progress bars, status messages) are skipped
    rather than aborting the entire parse — a trailing status line must not
    discard valid findings already parsed.
    """
    if not stdout or not stdout.strip():
        return []
    text = stdout.strip()
    # Try newline-delimited first (dalfox --json-pipe output).
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue  # skip non-JSON lines (progress/status), keep valid records
        if isinstance(obj, dict):
            records.append(obj)
        elif isinstance(obj, list):
            records.extend(item for item in obj if isinstance(item, dict))
    if records:
        return records
    # Fallback: whole stdout is a single JSON array or object.
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(obj, dict):
        return [obj]
    if isinstance(obj, list):
        return [item for item in obj if isinstance(item, dict)]
    return []


def parse(
    *, stdout: str, source: AdapterSource, artifacts: dict[str, bytes]
) -> tuple[Observation, ...]:
    """Parse dalfox JSON stdout into Observation records.

    Each finding becomes one Observation with `coverage_domain=web`,
    `cwe=(CWE-79,)`, `owasp=(A03:2021,)`. Severity is taken from the
    finding's `severity` field (default MEDIUM since dalfox flags are
    confirmed XSS by default).
    """
    records = _load_json_records(stdout)
    if not records:
        return ()
    observations: list[Observation] = []
    seen: set[str] = set()
    for idx, record in enumerate(records):
        # dalfox finding fields: type/message/data/param/poc/url/Severity
        url = record.get("url") or record.get("target") or record.get("host")
        param = record.get("param")
        # Build a stable asset_identity - prefer url+param to avoid dedup
        # collisions when the same URL has multiple reflected params.
        asset_identity = url or ""
        if param and isinstance(param, str):
            asset_identity = f"{url}?{param}" if url else param
        if not asset_identity or asset_identity in seen:
            continue
        seen.add(asset_identity)
        sev_str = str(record.get("severity") or record.get("Severity") or "medium").lower()
        severity = _SEVERITY_MAP.get(sev_str, Severity.MEDIUM)
        msg = record.get("message") or record.get("type") or "xss"
        title = f"xss: {msg}"
        raw = dict(record)
        raw.setdefault("cwe", "CWE-79")
        raw.setdefault("owasp", "A03:2021")
        observations.append(
            Observation(
                external_id=f"dalfox:{asset_identity}:{idx}",
                asset_identity=asset_identity,
                source=source,
                rule_id="dalfox.xss",
                rule_version=_UPSTREAM_VERSION,
                coverage_domain=CoverageDomain.WEB,
                title=title,
                severity=severity,
                confidence=0.85,
                cwe=("CWE-79",),
                cve=(),
                owasp=("A03:2021",),
                raw=raw,
            )
        )
    return tuple(observations)
