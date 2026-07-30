"""checkov adapter: IaC scan (Terraform / CloudFormation / K8s) (§8.2, cloud).

checkov (`checkov -f <iac> --json`) emits a JSON object with a `results`
field carrying `failed_checks[]` and `passed_checks[]`. Each failed check
has `check_id` (e.g. CKV_AWS_18), `check_name`, `file_path`, `resource`.
Each failed check becomes one Observation whose `asset_identity` is
`<file_path>:<resource>` and whose `cwe` tuple is populated from a curated
check-id -> CWE map so CoverageMatrix can credit the IaC coverage item.

checkov is MIT-licensed (no GPL marker needed). The parser is stdlib-only
(`json`) and returns an empty tuple on any parse failure.
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

_PARSER_ENTRYPOINT = "secopent_adapters.checkov:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "3.2.0"

# ---------------------------------------------------------------------------
# Curated checkov check-id prefix -> (CWE, OWASP) map.
# checkov ids follow CKV_<PROVIDER>_<NUM> (e.g. CKV_AWS_18 = ensure S3 log).
# Sources: checkov docs (bridgecrewio/checkov), OWASP Top 10 2021, CWE-1000.
# Mapping is by provider group, since individual numeric ids are too granular
# for a curated 1:1 map.
# ---------------------------------------------------------------------------
_CKV_CWE_MAP: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    # AWS S3 / storage exposure / public access
    "CKV_AWS_S3": (("CWE-732",), ("A01:2021",)),
    "CKV_AWS_18": (("CWE-778",), ("A09:2021",)),  # S3 access logging
    "CKV_AWS_19": (("CWE-311",), ("A02:2021",)),  # S3 encryption
    "CKV_AWS_20": (("CWE-732",), ("A01:2021",)),  # S3 not public read
    "CKV_AWS_21": (("CWE-732",), ("A01:2021",)),  # S3 versioning
    "CKV_AWS_52": (("CWE-693",), ("A05:2021",)),  # S3 MFA delete
    # IAM / access control
    "CKV_AWS_40": (("CWE-287",), ("A07:2021",)),  # IAM MFA
    "CKV_AWS_41": (("CWE-798",), ("A07:2021",)),  # IAM access key rotation
    "CKV_AWS_107": (("CWE-732",), ("A01:2021",)),  # IAM policy no admin
    # Encryption / KMS / TLS
    "CKV_AWS_KMS": (("CWE-311",), ("A02:2021",)),
    "CKV_AWS_7": (("CWE-311",), ("A02:2021",)),  # KMS rotation
    # Network / security group
    "CKV_AWS_23": (("CWE-284",), ("A05:2021",)),  # SG no 0.0.0.0/0 SSH
    "CKV_AWS_24": (("CWE-284",), ("A05:2021",)),  # SG no 0.0.0.0/0 RDP
    "CKV_AWS_260": (("CWE-284",), ("A05:2021",)),  # SG no 0.0.0.0/0 all
    # Logging / monitoring
    "CKV_AWS_CLOUDTRAIL": (("CWE-778",), ("A09:2021",)),
    "CKV_AWS_99": (("CWE-778",), ("A09:2021",)),  # CloudTrail multi-region
    # Generic provider-level fallbacks (CWE-693 = Protection Mechanism Failure)
    "CKV_AWS": (("CWE-693",), ("A05:2021",)),
    "CKV_GCP": (("CWE-693",), ("A05:2021",)),
    "CKV_AZURE": (("CWE-693",), ("A05:2021",)),
    "CKV_K8S": (("CWE-693",), ("A05:2021",)),
}

# Severity for checkov is not in the per-finding output by default. The
# Checkov framework classifies each check by impact; without a per-finding
# severity field we surface all failures as MEDIUM (config drift - high
# impact but not always exploitable). The curated map above gives a CWE
# attribution so CoverageMatrix can still credit the IaC coverage item.
_DEFAULT_SEVERITY = Severity.MEDIUM


def manifest() -> AdapterManifest:
    """Return the checkov AdapterManifest.

    checkov is MIT-licensed (no GPL marker / independent_process flag needed).
    risk_class=PASSIVE - it parses IaC files, never sends traffic.
    """
    return AdapterManifest(
        id="checkov",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="MIT",
        upstream=AdapterUpstream(
            name="checkov",
            url="https://github.com/bridgecrewio/checkov",
            version=_UPSTREAM_VERSION,
            digest="sha256:checkov-" + _UPSTREAM_VERSION,
        ),
        risk_class=RiskClass.PASSIVE,
        coverage_domain=(CoverageDomain.CLOUD,),
        input_schema="schema://checkov/input.json",
        output_schema="schema://checkov/output.json",
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


def _map_check_id(check_id: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Map a checkov check_id to (cwe, owasp) via prefix matching.

    Try exact match first, then provider-level prefix (CKV_AWS, CKV_GCP, etc).
    Returns ((), ()) for unknown check ids.
    """
    if not check_id:
        return (), ()
    cid = check_id.upper()
    # Exact match.
    if cid in _CKV_CWE_MAP:
        return _CKV_CWE_MAP[cid]
    # Provider-level prefix match (CKV_AWS_*, CKV_GCP_*, ...).
    for prefix, mapping in _CKV_CWE_MAP.items():
        if cid.startswith(prefix + "_") or cid == prefix:
            return mapping
    return (), ()


def _load_checkov_json(stdout: str) -> dict[str, Any] | list[Any] | None:
    """Parse checkov JSON stdout. Returns None on any parse failure.

    checkov emits a single object when one framework is scanned, or a JSON array
    of per-framework objects when several are (e.g. a directory holding both a
    Dockerfile and Kubernetes manifests). Both shapes are accepted here and
    normalized by ``parse``.
    """
    if not stdout or not stdout.strip():
        return None
    try:
        obj = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict | list):
        return None
    return obj


def _maybe_extract_cve(reference: Any) -> tuple[str, ...]:
    """Extract CVE IDs from a checkov check's `guideline` URL or references."""
    if not reference:
        return ()
    if isinstance(reference, str):
        reference = [reference]
    cves: list[str] = []
    cve_re = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    for ref in reference:
        if not isinstance(ref, str):
            continue
        for match in cve_re.findall(ref):
            cves.append(match.upper())
    return tuple(dict.fromkeys(cves))


def parse(
    *, stdout: str, source: AdapterSource, artifacts: dict[str, bytes]
) -> tuple[Observation, ...]:
    """Parse checkov IaC scan JSON into Observation records.

    checkov JSON schema:
        {
          "results": {
            "failed_checks": [
              {
                "check_id": "CKV_AWS_20",
                "check_name": "S3 Bucket has an ACL defined which allows public access",
                "check_type": "terraform",
                "code_block": [...],
                "file_path": "/path/to/main.tf",
                "file_abs_path": "...",
                "repo_file_path": "...",
                "resource": "aws_s3_bucket.public",
                "evaluations": [...],
                "check_class": "..."
              },
              ...
            ],
            "passed_checks": [...],
            "skipped_checks": [...],
            "parsing_errors": [...]
          },
          "summary": {
            "passed": 1,
            "failed": 2,
            "skipped": 0,
            "parsing_errors": 0
          }
        }

    Each failed check becomes one Observation with `coverage_domain=cloud`,
    `asset_identity=<file_path>:<resource>`, and `cwe` populated from the
    curated check-id map. `raw` preserves `check_id` / `check_name` /
    `file_path` so audit/replay can reconstruct the scan.
    """
    obj = _load_checkov_json(stdout)
    if obj is None:
        return ()
    # checkov emits one object per scanned framework; a multi-framework directory
    # yields a JSON array. Normalize both shapes into a single failed-check list.
    blocks = obj if isinstance(obj, list) else [obj]
    failed: list[Any] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        results = block.get("results")
        if not isinstance(results, dict):
            continue
        checks = results.get("failed_checks")
        if isinstance(checks, list):
            failed.extend(checks)
    if not failed:
        return ()
    observations: list[Observation] = []
    seen: set[str] = set()
    idx = 0
    for check in failed:
        if not isinstance(check, dict):
            continue
        check_id = _safe_str(check.get("check_id") or check.get("CheckId"))
        if not check_id:
            continue
        check_name = _safe_str(
            check.get("check_name") or check.get("check_title") or check_id
        )
        file_path = _safe_str(
            check.get("file_path") or check.get("file_path_") or "<unknown>"
        )
        resource = _safe_str(check.get("resource") or check.get("resource_address"))
        asset_identity = f"{file_path}:{resource or check_id}"
        if asset_identity in seen:
            continue
        seen.add(asset_identity)

        cwe, owasp = _map_check_id(check_id)
        cve = _maybe_extract_cve(
            check.get("guideline") or check.get("references")
        )

        raw: dict[str, Any] = dict(check)
        # Normalize the check_id key so downstream always finds it.
        raw.setdefault("check_id", check_id)

        observations.append(
            Observation(
                external_id=f"checkov:{check_id}:{file_path}:{idx}",
                asset_identity=asset_identity,
                source=source,
                rule_id=check_id,
                rule_version=_UPSTREAM_VERSION,
                coverage_domain=CoverageDomain.CLOUD,
                title=check_name,
                severity=_DEFAULT_SEVERITY,
                confidence=0.9,
                cwe=cwe,
                cve=cve,
                owasp=owasp,
                raw=raw,
            )
        )
        idx += 1
    return tuple(observations)
