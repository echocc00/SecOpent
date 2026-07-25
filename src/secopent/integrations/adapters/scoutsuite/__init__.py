"""scoutsuite adapter: multi-cloud security audit (AWS/Azure/GCP) (§8.2, cloud).

ScoutSuite (`scout aws --report-dir <dir>`) writes a consolidated results JSON
whose shape is::

    {
      "account_id": "123456789012",
      "provider_code": "aws",
      "provider_name": "Amazon Web Services",
      "services": {
        "<service>": {
          "findings": {
            "<finding_key>": {
              "checked_items": 1,
              "flagged_items": 1,
              "description": "Root account has no hardware MFA",
              "level": "danger",          # danger / warning
              "items": ["iam.credential_reports.id.root"]
            }
          }
        }
      }
    }

Each finding with ``flagged_items > 0`` becomes one Observation whose
``asset_identity`` is ``<account>:<service>:<finding_key>`` and whose ``raw``
preserves the original finding so audit/CoverageMatrix can reconstruct the
scan. The curated ``_FINDING_CWE_MAP`` maps common ScoutSuite finding-key
prefixes (iam / s3 / ec2 / cloudtrail / kms / rds ...) to CWE / OWASP Top-10
classes so findings auto-satisfy the corresponding cloud coverage items;
unknown keys fall back to an empty tuple.

ScoutSuite is **GPL-2.0** licensed. Per §8.2, GPL tools MUST be invoked as an
independent subprocess rather than embedded as a library (to keep the
aggregator's license clean). The manifest therefore carries a GPL-2 license
string AND an ``independent_process`` marker in ``permissions`` so the
execution layer can route it to subprocess isolation. The parser itself is
stdlib-only (``json``) and returns an empty tuple on any parse failure.
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

_PARSER_ENTRYPOINT = "secopent_adapters.scoutsuite:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "5.13.0"

# ---------------------------------------------------------------------------
# Curated ScoutSuite finding-key prefix -> (CWE, OWASP) map.
# ScoutSuite finding keys are kebab-case service-prefixed identifiers, e.g.
# "iam-root-no-hardware-mfa", "s3-bucket-world-acl", "cloudtrail-no-logging".
# Sources: ScoutSuite rulesets (nccgroup/ScoutSuite), OWASP Top 10 2021,
# CWE-1000 view.
# ---------------------------------------------------------------------------
_FINDING_CWE_MAP: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    # IAM / credential hygiene
    "iam": (("CWE-287",), ("A07:2021",)),
    # Logging / monitoring
    "cloudtrail": (("CWE-778",), ("A09:2021",)),
    "logging": (("CWE-778",), ("A09:2021",)),
    # Encryption / TLS
    "kms": (("CWE-311",), ("A02:2021",)),
    "elb": (("CWE-295",), ("A02:2021",)),
    # Network / exposure
    "ec2": (("CWE-284",), ("A05:2021",)),
    "vpc": (("CWE-284",), ("A05:2021",)),
    "security-group": (("CWE-284",), ("A05:2021",)),
    # Storage exposure
    "s3": (("CWE-732",), ("A01:2021",)),
    # DB hardening
    "rds": (("CWE-284",), ("A05:2021",)),
    "redshift": (("CWE-284",), ("A05:2021",)),
}

# ScoutSuite "level" -> Severity. danger -> HIGH, warning -> MEDIUM.
_SEVERITY_MAP: dict[str, Severity] = {
    "danger": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.INFO,
}


def manifest() -> AdapterManifest:
    """Return the scoutsuite AdapterManifest.

    ScoutSuite is GPL-2.0-licensed (§8.2 table) and MUST run as an independent
    subprocess, never embedded as a library. The manifest carries both facts:
    a GPL-2 license string and an ``independent_process`` marker in
    ``permissions``. risk_class=PASSIVE - it reads cloud config APIs, never
    sends traffic to user workloads.
    """
    return AdapterManifest(
        id="scoutsuite",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="GPL-2.0-or-later",
        upstream=AdapterUpstream(
            name="ScoutSuite",
            url="https://github.com/nccgroup/ScoutSuite",
            version=_UPSTREAM_VERSION,
            digest="sha256:scoutsuite-" + _UPSTREAM_VERSION,
        ),
        risk_class=RiskClass.PASSIVE,
        coverage_domain=(CoverageDomain.CLOUD,),
        input_schema="schema://scoutsuite/input.json",
        output_schema="schema://scoutsuite/output.json",
        network_policy="scoped-egress",
        parser=_PARSER_ENTRYPOINT,
        fixtures=(
            "fixtures/positive.json",
            "fixtures/negative.json",
            "fixtures/timeout.txt",
            "fixtures/malformed.json",
        ),
        # independent_process marks this GPL tool for subprocess isolation.
        permissions=("passive", "independent_process"),
    )


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _map_finding_key(finding_key: str, service: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Map a ScoutSuite finding key to (cwe, owasp) via prefix matching.

    Try the finding key first (it is usually service-prefixed, e.g.
    "iam-root-no-hardware-mfa"), then fall back to the service name.
    Returns ((), ()) for unknown keys.
    """
    candidates = [finding_key.lower(), service.lower()]
    for candidate in candidates:
        if not candidate:
            continue
        for prefix, mapping in _FINDING_CWE_MAP.items():
            if candidate.startswith(prefix):
                return mapping
    return (), ()


def _load_scoutsuite_json(stdout: str) -> dict[str, Any] | None:
    """Parse ScoutSuite results JSON stdout. Returns None on any failure."""
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
    """Parse ScoutSuite results JSON into Observation records.

    Each flagged finding (``flagged_items > 0``) becomes one Observation with
    ``coverage_domain=cloud``, ``asset_identity=<account>:<service>:<key>``,
    severity from the finding's ``level`` field, and CWE/OWASP populated from
    the curated finding-key prefix map. ``raw`` preserves the original finding
    dict plus ``service`` / ``finding_key`` so audit/replay can reconstruct the
    scan. Findings with zero flagged items are skipped (no actual risk).
    """
    obj = _load_scoutsuite_json(stdout)
    if obj is None:
        return ()
    account = _safe_str(obj.get("account_id") or obj.get("accountId") or "unknown")
    services = obj.get("services")
    if not isinstance(services, dict):
        return ()
    observations: list[Observation] = []
    seen: set[str] = set()
    idx = 0
    for service, service_obj in services.items():
        if not isinstance(service_obj, dict):
            continue
        findings = service_obj.get("findings")
        if not isinstance(findings, dict):
            continue
        for finding_key, finding in findings.items():
            if not isinstance(finding, dict):
                continue
            flagged = finding.get("flagged_items", 0)
            try:
                flagged_count = int(flagged)
            except (TypeError, ValueError):
                flagged_count = 0
            if flagged_count <= 0:
                # No flagged items -> no finding to surface.
                continue
            level = _safe_str(finding.get("level") or "warning").lower()
            severity = _SEVERITY_MAP.get(level, Severity.MEDIUM)
            description = _safe_str(finding.get("description") or finding_key)

            asset_identity = f"{account}:{service}:{finding_key}"
            if asset_identity in seen:
                continue
            seen.add(asset_identity)

            cwe, owasp = _map_finding_key(finding_key, service)

            raw: dict[str, Any] = dict(finding)
            raw.setdefault("service", service)
            raw.setdefault("finding_key", finding_key)

            observations.append(
                Observation(
                    external_id=f"scoutsuite:{service}:{finding_key}:{account}:{idx}",
                    asset_identity=asset_identity,
                    source=source,
                    rule_id=finding_key,
                    rule_version=_UPSTREAM_VERSION,
                    coverage_domain=CoverageDomain.CLOUD,
                    title=description,
                    severity=severity,
                    confidence=0.9,
                    cwe=cwe,
                    cve=(),
                    owasp=owasp,
                    raw=raw,
                )
            )
            idx += 1
    return tuple(observations)
