"""ZAP adapter: OWASP ZAP active scanner (§8.2, active, Standalone-only).

ZAP active scanning is heavy and noisy - it sends attack payloads and can
take a long time on large sites. It is therefore NOT available in Lite
engagement profiles; the manifest marks itself `standalone-only` via the
`permissions` tuple so the profile selector / AdapterRunner can gate ZAP
out of Lite runs.

ZAP emits a JSON report with an `alerts` array. Each alert carries a
`pluginid` (ZAP scan rule ID) and a `cweid` ("CWE-ID" in ZAP parlance). The
parser maps the `cweid` into the Observation's `cwe` tuple so CoverageMatrix
can attribute coverage; OWASP is mapped from a small curated ZAP-plugin ->
OWASP table (the most common plugins only).
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

_PARSER_ENTRYPOINT = "secopent_adapters.zap:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "2.15.0"

# Curated ZAP pluginid -> OWASP mapping. Only the most common active-scan
# plugins are mapped; unmapped plugins surface cwe from cweid but no owasp.
_PLUGIN_OWASP: dict[str, str] = {
    "40018": "A03:2021",  # SQL Injection
    "40014": "A03:2021",  # XSS
    "40019": "A03:2021",  # CRLF Injection
    "40020": "A03:2021",  # RCE
    "40024": "A01:2021",  # Path Traversal
    "40025": "A01:2021",  # IDOR
    "10202": "A02:2021",  # SSL
    "10027": "A05:2021",  # Cookie misconfig
    "10010": "A05:2021",  # Cookie no HttpOnly
    "10017": "A05:2021",  # Source disclosure
    "10021": "A05:2021",  # X-Frame-Options
    "10038": "A05:2021",  # Content Security Policy
    "10028": "A07:2021",  # Weak auth
    "10098": "A05:2021",  # Cross Site Tracing
}

# ZAP risk strings -> Severity enum.
_RISK_SEVERITY: dict[str, Severity] = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


def manifest() -> AdapterManifest:
    """Return the ZAP AdapterManifest.

    ZAP active scan is `risk_class=ACTIVE` and `standalone-only` (not for
    Lite engagements) via the `permissions` tuple. The AdapterRunner /
    profile selector reads this marker to gate ZAP out of Lite runs.
    """
    return AdapterManifest(
        id="zap",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="Apache-2.0",
        upstream=AdapterUpstream(
            name="zap",
            url="https://github.com/zaproxy/zaproxy",
            version=_UPSTREAM_VERSION,
            digest="sha256:zap-" + _UPSTREAM_VERSION,
        ),
        risk_class=RiskClass.ACTIVE,
        coverage_domain=(CoverageDomain.WEB,),
        input_schema="schema://zap/input.json",
        output_schema="schema://zap/output.json",
        network_policy="scoped-egress",
        parser=_PARSER_ENTRYPOINT,
        fixtures=(
            "fixtures/positive.json",
            "fixtures/negative.json",
            "fixtures/timeout.txt",
            "fixtures/malformed.json",
        ),
        permissions=("active", "standalone-only"),
    )


def _load_alerts(stdout: str) -> list[dict[str, Any]]:
    """Parse the ZAP JSON report.

    ZAP's JSON report is `{"site": [..., {"alerts": [...]}]}` or a flat
    `{"alerts": [...]}`. Returns `[]` on any parse failure.
    """
    if not stdout or not stdout.strip():
        return []
    text = stdout.strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(obj, list):
        return [item for item in obj if isinstance(item, dict)]
    if not isinstance(obj, dict):
        return []
    # Flat form: {"alerts": [...]}
    alerts = obj.get("alerts")
    if isinstance(alerts, list):
        return [a for a in alerts if isinstance(a, dict)]
    # Nested form: {"site": [{"alerts": [...]}, ...]}
    sites = obj.get("site")
    if isinstance(sites, list):
        out: list[dict[str, Any]] = []
        for site in sites:
            if not isinstance(site, dict):
                continue
            site_alerts = site.get("alerts")
            if isinstance(site_alerts, list):
                out.extend(a for a in site_alerts if isinstance(a, dict))
        return out
    return []


def parse(
    *, stdout: str, source: AdapterSource, artifacts: dict[str, bytes]
) -> tuple[Observation, ...]:
    """Parse ZAP JSON report into Observation records.

    Each alert becomes one Observation with `coverage_domain=web`, `cwe`
    populated from `cweid` (when present and non-zero), and `owasp`
    populated from the curated plugin map.
    """
    records = _load_alerts(stdout)
    if not records:
        return ()
    observations: list[Observation] = []
    seen: set[tuple[str, str]] = set()
    for idx, record in enumerate(records):
        pluginid = str(record.get("pluginid") or record.get("id") or "")
        # ZAP cweid is a string; "0" / "-1" mean unmapped.
        cweid_raw = record.get("cweid") or record.get("cwe") or "0"
        try:
            cwe_num = int(str(cweid_raw))
        except (TypeError, ValueError):
            cwe_num = 0
        cwe: tuple[str, ...] = (f"CWE-{cwe_num}",) if cwe_num > 0 else ()
        owasp_str = _PLUGIN_OWASP.get(pluginid)
        owasp: tuple[str, ...] = (owasp_str,) if owasp_str else ()
        url = record.get("url") or record.get("instance") or record.get("host") or ""
        alert_name = record.get("alert") or record.get("name") or "zap alert"
        key = (pluginid, str(url))
        if not url or key in seen:
            continue
        seen.add(key)
        risk_str = str(record.get("risk") or record.get("riskcode") or "info").lower()
        # riskcode is numeric: 3=high, 2=medium, 1=low, 0=info.
        if risk_str.isdigit():
            risk_str = {"3": "high", "2": "medium", "1": "low", "0": "info"}.get(
                risk_str, "info"
            )
        severity = _RISK_SEVERITY.get(risk_str, Severity.INFO)
        raw = dict(record)
        raw.setdefault("pluginid", pluginid)
        observations.append(
            Observation(
                external_id=f"zap:{pluginid}:{url}:{idx}",
                asset_identity=str(url),
                source=source,
                rule_id=f"zap.{pluginid}" if pluginid else "zap.alert",
                rule_version=_UPSTREAM_VERSION,
                coverage_domain=CoverageDomain.WEB,
                title=str(alert_name),
                severity=severity,
                confidence=0.8,
                cwe=cwe,
                cve=(),
                owasp=owasp,
                raw=raw,
            )
        )
    return tuple(observations)
