"""prowler adapter: AWS/Azure/GCP config audit (§8.2, cloud domain).

Prowler (`prowler aws -M json`) emits a JSON array of finding objects, each
keyed by `CheckId` / `Severity` / `Status` / `Region` / `AccountId` /
`CheckTitle`. Each PASS/FAIL finding yields one Observation whose
`asset_identity` is `<account>:<region>:<check_id>` and whose `raw` carries
the original CIS check item so CoverageMatrix can credit the corresponding
cloud CIS coverage item.

The curated `_CIS_CWE_MAP` maps common Prowler check-id prefixes (e.g.
`check_7_1`, `iam_user_mfa`, `s3_bucket_public_read`) to CWE / OWASP Top-10
classes so findings auto-satisfy the corresponding cloud coverage items.
Unknown check ids fall back to an empty CWE/OWASP tuple - the finding still
surfaces as an Observation, just without coverage attribution.

Prowler is Apache-2.0 (no GPL marker needed). The parser is stdlib-only
(`json`) and returns an empty tuple on any parse failure so a malformed
tool stream never takes down the runner.
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

_PARSER_ENTRYPOINT = "secopent_adapters.prowler:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "4.6.0"

# ---------------------------------------------------------------------------
# Curated Prowler check-id prefix -> (CWE, OWASP) map.
# Keys are lower-case prefixes matched against the CheckId / check_id field.
# Sources: CIS AWS Foundations Benchmark 1.4 / 2.0, OWASP Top 10 2021,
# CWE-1000 view. Prowler check taxonomy:
#   https://docs.prowler.cloud/projects/prowler-open-source/
# ---------------------------------------------------------------------------
_CIS_CWE_MAP: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    # IAM / MFA / credential hygiene (CIS 1.x)
    "iam_user_mfa": (("CWE-287",), ("A07:2021",)),
    "iam_mfa": (("CWE-287",), ("A07:2021",)),
    "iam_root": (("CWE-287",), ("A07:2021",)),
    "iam_password": (("CWE-521",), ("A07:2021",)),
    "iam_access_key": (("CWE-798",), ("A07:2021",)),
    "iam_policy": (("CWE-732",), ("A01:2021",)),
    # Logging / monitoring (CIS 2.x, 3.x)
    "cloudtrail": (("CWE-778",), ("A09:2021",)),
    "cloudwatch": (("CWE-778",), ("A09:2021",)),
    "config": (("CWE-778",), ("A09:2021",)),
    # Encryption / TLS (CIS 4.x)
    "kms": (("CWE-311",), ("A02:2021",)),
    "tls": (("CWE-295",), ("A02:2021",)),
    "ssl": (("CWE-295",), ("A02:2021",)),
    # Network / exposure (CIS 5.x)
    "security_group": (("CWE-284",), ("A05:2021",)),
    "nacl": (("CWE-284",), ("A05:2021",)),
    "vpc": (("CWE-284",), ("A05:2021",)),
    # S3 / storage exposure
    "s3_bucket": (("CWE-732",), ("A01:2021",)),
    "s3": (("CWE-732",), ("A01:2021",)),
    # RDS / DB hardening
    "rds": (("CWE-284",), ("A05:2021",)),
    # CIS-numbered checks (Prowler legacy check_7_1, check_2_1 etc.)
    "check_2": (("CWE-778",), ("A09:2021",)),
    "check_4": (("CWE-311",), ("A02:2021",)),
    "check_5": (("CWE-284",), ("A05:2021",)),
}

# Severity string -> Severity enum. Prowler uses "critical"/"high"/"medium"/
# "low"/"info"; we lowercase and map. Status "PASS" -> INFO (no finding).
_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


def manifest() -> AdapterManifest:
    """Return the prowler AdapterManifest.

    Prowler is Apache-2.0 (no GPL marker / independent_process flag needed).
    risk_class=PASSIVE - it reads cloud config APIs, never sends traffic to
    user workloads.
    """
    return AdapterManifest(
        id="prowler",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="Apache-2.0",
        upstream=AdapterUpstream(
            name="prowler",
            url="https://github.com/prowler-cloud/prowler",
            version=_UPSTREAM_VERSION,
            digest="sha256:prowler-" + _UPSTREAM_VERSION,
        ),
        risk_class=RiskClass.PASSIVE,
        coverage_domain=(CoverageDomain.CLOUD,),
        input_schema="schema://prowler/input.json",
        output_schema="schema://prowler/output.json",
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


def _map_check_id(check_id: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Map a Prowler check_id to (cwe, owasp) via prefix matching.

    Returns ((), ()) for unknown check ids.
    """
    if not check_id:
        return (), ()
    cid = check_id.lower()
    for prefix, mapping in _CIS_CWE_MAP.items():
        if cid.startswith(prefix):
            return mapping
    return (), ()


def _safe_str(value: Any) -> str:
    """Coerce a JSON field to str; return '' for None/missing."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _load_prowler_json(stdout: str) -> list[dict[str, Any]]:
    """Parse Prowler JSON output (array of finding dicts).

    Prowler `-M json` emits a JSON array. Returns `[]` on any parse error.
    """
    if not stdout or not stdout.strip():
        return []
    try:
        obj = json.loads(stdout)
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
    """Parse Prowler JSON stdout into Observation records.

    Each finding dict has keys (Prowler v3+ JSON schema):
        {
          "CheckId": "iam_user_mfa",
          "CheckTitle": "Ensure MFA is enabled for ...",
          "Severity": "high",
          "Status": "FAIL",            # PASS/FAIL
          "Region": "us-east-1",
          "AccountId": "123456789012",
          "ResourceArn": "arn:aws:iam::...",
          "Description": "...",
          "CheckType": [...],
          ...
        }

    Each FAIL finding becomes one Observation with `coverage_domain=cloud`,
    `asset_identity=<account>:<region>:<check_id>`, severity from the
    finding's Severity field, and CWE/OWASP populated from the curated
    check-id prefix map. PASS findings surface as INFO Observations so
    CoverageMatrix can still credit the CIS coverage item as executed.
    """
    records = _load_prowler_json(stdout)
    if not records:
        return ()
    observations: list[Observation] = []
    seen: set[str] = set()
    for idx, record in enumerate(records):
        # Prowler v3 uses Capitalized keys; v2 used snake_case. Accept both.
        check_id = _safe_str(
            record.get("CheckId") or record.get("check_id") or record.get("checkid")
        )
        if not check_id:
            # No check id -> cannot credit a coverage item; skip.
            continue
        account = _safe_str(
            record.get("AccountId") or record.get("account_id") or record.get("account")
        )
        region = _safe_str(
            record.get("Region") or record.get("region") or "global"
        )
        title = _safe_str(
            record.get("CheckTitle") or record.get("check_title") or check_id
        )
        severity_str = _safe_str(
            record.get("Severity") or record.get("severity") or "info"
        ).lower()
        severity = _SEVERITY_MAP.get(severity_str, Severity.INFO)
        status = _safe_str(record.get("Status") or record.get("status") or "").upper()
        # PASS findings -> INFO severity (no actual risk).
        if status == "PASS":
            severity = Severity.INFO

        asset_identity = f"{account or 'unknown'}:{region}:{check_id}"
        if asset_identity in seen:
            continue
        seen.add(asset_identity)

        cwe, owasp = _map_check_id(check_id)

        raw: dict[str, Any] = dict(record)
        # Normalize the check_id key so downstream always finds it.
        raw.setdefault("check_id", check_id)

        observations.append(
            Observation(
                external_id=f"prowler:{check_id}:{account}:{region}:{idx}",
                asset_identity=asset_identity,
                source=source,
                rule_id=check_id,
                rule_version=_UPSTREAM_VERSION,
                coverage_domain=CoverageDomain.CLOUD,
                title=title,
                severity=severity,
                confidence=0.9,
                cwe=cwe,
                cve=(),
                owasp=owasp,
                raw=raw,
            )
        )
    return tuple(observations)
