"""trivy adapter: container image + IaC + filesystem scan (§8.2, cloud domain).

Trivy (`trivy image --format json <image>`) emits a JSON object with a
`Results` array; each `Results[i]` carries a `Vulnerabilities[]` list keyed
by `VulnerabilityID` (a CVE), `PkgName`, `Severity`, `InstalledVersion`,
`FixedVersion`. Each vulnerability becomes one Observation whose
`asset_identity` is `<target>:<pkg>` and whose `cve` tuple is populated from
`VulnerabilityID` so CoverageMatrix can credit the corresponding cloud
coverage item.

Trivy is Apache-2.0 (no GPL marker needed). The parser is stdlib-only
(`json`) and returns an empty tuple on any parse failure so a malformed
tool stream never takes down the runner.
"""
from __future__ import annotations

import json
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

_PARSER_ENTRYPOINT = "secopent_adapters.trivy:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "0.55.0"

# Compiled once. Trivy VulnerabilityID is normally CVE-YYYY-NNNNN; we also
# accept other vulnerability identifiers (GHSA, RUSTSEC, etc.) but only
# CVE-shaped IDs are pushed into the Observation's `cve` tuple.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Severity string -> Severity enum. Trivy uses "CRITICAL"/"HIGH"/"MEDIUM"/
# "LOW"/"UNKNOWN"; we lowercase and map.
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "unknown": Severity.INFO,
    "none": Severity.INFO,
}


def manifest() -> AdapterManifest:
    """Return the trivy AdapterManifest.

    Trivy is Apache-2.0 (no GPL marker / independent_process flag needed).
    risk_class=PASSIVE - it reads container images / IaC files / filesystems
    and never sends traffic to user workloads.
    """
    return AdapterManifest(
        id="trivy",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="Apache-2.0",
        upstream=AdapterUpstream(
            name="trivy",
            url="https://github.com/aquasecurity/trivy",
            version=_UPSTREAM_VERSION,
            digest="sha256:trivy-" + _UPSTREAM_VERSION,
        ),
        risk_class=RiskClass.PASSIVE,
        coverage_domain=(CoverageDomain.CLOUD,),
        input_schema="schema://trivy/input.json",
        output_schema="schema://trivy/output.json",
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


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _map_severity(sev_str: str) -> Severity:
    return _SEVERITY_MAP.get(sev_str.lower(), Severity.INFO)


def _extract_cve(vid: str) -> tuple[str, ...]:
    """Extract CVE IDs from a VulnerabilityID string.

    Most Trivy VulnerabilityIDs ARE CVEs (e.g. "CVE-2024-12345"); we also
    accept GHSA-style IDs and parse embedded CVEs out of them.
    """
    if not vid:
        return ()
    matches = _CVE_RE.findall(vid)
    if matches:
        return tuple(dict.fromkeys(m.upper() for m in matches))
    # If the vid is itself a CVE-shaped string the regex would have caught
    # it; for non-CVE identifiers we return empty (CoverageMatrix credits
    # CVEs, not GHSA IDs).
    return ()


def _load_trivy_json(stdout: str) -> dict[str, Any] | None:
    """Parse Trivy JSON stdout. Returns None on any parse failure.

    Trivy emits a top-level object with `Results` (list) and `ArtifactName`.
    """
    if not stdout or not stdout.strip():
        return None
    try:
        obj = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    return obj


def parse(
    *, stdout: str, source: AdapterSource, artifacts: dict[str, bytes]
) -> tuple[Observation, ...]:
    """Parse Trivy image/IaC/filesystem scan JSON into Observation records.

    Trivy JSON schema:
        {
          "SchemaVersion": 2,
          "ArtifactName": "alpine:3.18",
          "ArtifactType": "container_image",
          "Results": [
            {
              "Target": "alpine:3.18 (alpine 3.18)",
              "Class": "os-pkgs",
              "Type": "alpine",
              "Vulnerabilities": [
                {
                  "VulnerabilityID": "CVE-2024-12345",
                  "PkgName": "openssl",
                  "InstalledVersion": "3.1.0-r0",
                  "FixedVersion": "3.1.1-r0",
                  "Severity": "HIGH",
                  "Title": "openssl: ...",
                  "Description": "...",
                  "CweIDs": ["CWE-20"],
                  "References": [...]
                }
              ]
            }
          ]
        }

    Each Vulnerability becomes one Observation with `coverage_domain=cloud`,
    `asset_identity=<artifact>:<pkg>`, severity from the finding, and `cve`
    populated from VulnerabilityID. `raw` preserves PkgName,
    VulnerabilityID, InstalledVersion, FixedVersion so audit/replay can
    reconstruct the scan.
    """
    obj = _load_trivy_json(stdout)
    if obj is None:
        return ()
    artifact_name = _safe_str(obj.get("ArtifactName") or obj.get("artifact_name"))
    results = obj.get("Results")
    if not isinstance(results, list):
        return ()
    observations: list[Observation] = []
    seen: set[str] = set()
    idx = 0
    for result in results:
        if not isinstance(result, dict):
            continue
        target = _safe_str(result.get("Target") or result.get("target") or artifact_name)
        vulns = result.get("Vulnerabilities") or result.get("vulnerabilities")
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            vid = _safe_str(
                vuln.get("VulnerabilityID") or vuln.get("vulnerability_id")
            )
            pkg = _safe_str(vuln.get("PkgName") or vuln.get("pkg_name"))
            if not vid or not pkg:
                continue
            asset_identity = f"{artifact_name or target}:{pkg}:{vid}"
            if asset_identity in seen:
                continue
            seen.add(asset_identity)
            sev_str = _safe_str(vuln.get("Severity") or vuln.get("severity"))
            severity = _map_severity(sev_str)
            cve = _extract_cve(vid)
            # CWEs from Trivy's CweIDs field (e.g. ["CWE-20"]).
            cwe_ids = vuln.get("CweIDs") or vuln.get("cwe_ids") or []
            if isinstance(cwe_ids, str):
                cwe_ids = [cwe_ids]
            cwes: list[str] = []
            for c in cwe_ids:
                cs = _safe_str(c)
                if cs and cs.startswith("CWE-"):
                    cwes.append(cs.upper())
            title = _safe_str(vuln.get("Title") or vuln.get("title") or vid)
            raw: dict[str, Any] = dict(vuln)
            # Normalize keys so downstream always finds PkgName / VulnerabilityID.
            raw.setdefault("PkgName", pkg)
            raw.setdefault("VulnerabilityID", vid)
            raw["artifact"] = artifact_name
            raw["target"] = target

            observations.append(
                Observation(
                    external_id=f"trivy:{vid}:{pkg}:{idx}",
                    asset_identity=asset_identity,
                    source=source,
                    rule_id=vid,
                    rule_version=_UPSTREAM_VERSION,
                    coverage_domain=CoverageDomain.CLOUD,
                    title=title,
                    severity=severity,
                    confidence=0.9,
                    cwe=tuple(sorted(set(cwes))),
                    cve=cve,
                    owasp=(),
                    raw=raw,
                )
            )
            idx += 1
    return tuple(observations)
