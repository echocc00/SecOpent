"""kube_bench adapter: Kubernetes CIS benchmark (§8.2, cloud domain).

kube-bench (`kube-bench --json`) emits a JSON array of `Controls` objects,
each carrying a `Results[]` list keyed by `id` (CIS control id),
`text` (description), `status` (PASS/FAIL/WARN), `test_number`, `node_type`.
Each failing control becomes one Observation whose `asset_identity` is
`<node>:<control_id>` and whose `raw` preserves the CIS control id so
CoverageMatrix can credit the corresponding CIS benchmark coverage item.

kube-bench is Apache-2.0 (no GPL marker needed). The parser is stdlib-only
(`json`) and returns an empty tuple on any parse failure.
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

_PARSER_ENTRYPOINT = "secopent_adapters.kube_bench:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "0.8.0"

# Map kube-bench status -> Severity. PASS / WARN -> INFO (no actionable risk);
# FAIL -> HIGH (CIS benchmark failure is high-impact config drift).
_STATUS_SEVERITY: dict[str, Severity] = {
    "FAIL": Severity.HIGH,
    "WARN": Severity.INFO,
    "PASS": Severity.INFO,
    "INFO": Severity.INFO,
    "MANUAL": Severity.INFO,
}


def manifest() -> AdapterManifest:
    """Return the kube_bench AdapterManifest.

    kube-bench is Apache-2.0 (no GPL marker / independent_process flag needed).
    risk_class=PASSIVE - it reads kubelet / API server config, never sends
    traffic to user workloads.
    """
    return AdapterManifest(
        id="kube_bench",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="Apache-2.0",
        upstream=AdapterUpstream(
            name="kube-bench",
            url="https://github.com/aquasecurity/kube-bench",
            version=_UPSTREAM_VERSION,
            digest="sha256:kube-bench-" + _UPSTREAM_VERSION,
        ),
        risk_class=RiskClass.PASSIVE,
        coverage_domain=(CoverageDomain.CLOUD,),
        input_schema="schema://kube_bench/input.json",
        output_schema="schema://kube_bench/output.json",
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


def _load_kube_bench_json(stdout: str) -> list[dict[str, Any]]:
    """Parse kube-bench JSON stdout (array of Controls objects).

    Returns `[]` on any parse error.
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
    """Parse kube-bench JSON stdout into Observation records.

    kube-bench JSON schema (one element per Controls section):
        [
          {
            "id": "1",
            "text": "Master Node Security Configuration",
            "node_type": "master",
            "tests": [
              {
                "section": "1.1",
                "pass": 5,
                "fail": 2,
                "warn": 0,
                "results": [
                  {
                    "test_number": "1.1.1",
                    "test_desc": "Ensure API server pod specification ...",
                    "status": "FAIL",
                    "audit": "/bin/ps -ef | grep kube-apiserver",
                    "AuditConfig": "...",
                    "expected_result": "..."
                  },
                  ...
                ]
              }
            ],
            "total_pass": 5,
            "total_fail": 2
          },
          ...
        ]

    Each `results[]` item becomes one Observation with `coverage_domain=cloud`,
    `asset_identity=<node_type>:<test_number>`, severity from the status
    (FAIL -> HIGH), and `raw` preserving `id` (control section id) and
    `test_number` (CIS item id) so CoverageMatrix can credit the CIS
    benchmark coverage item.
    """
    controls_list = _load_kube_bench_json(stdout)
    if not controls_list:
        return ()
    observations: list[Observation] = []
    seen: set[str] = set()
    idx = 0
    for controls in controls_list:
        if not isinstance(controls, dict):
            continue
        control_id = _safe_str(controls.get("id") or controls.get("control_id"))
        node_type = _safe_str(controls.get("node_type") or controls.get("nodeType"))
        tests = controls.get("tests")
        if not isinstance(tests, list):
            continue
        for test_group in tests:
            if not isinstance(test_group, dict):
                continue
            results = test_group.get("results")
            if not isinstance(results, list):
                continue
            for result in results:
                if not isinstance(result, dict):
                    continue
                test_number = _safe_str(
                    result.get("test_number") or result.get("testNumber")
                )
                if not test_number:
                    continue
                status = _safe_str(result.get("status")).upper()
                severity = _STATUS_SEVERITY.get(status, Severity.INFO)
                # Skip PASS / INFO results - they don't surface actionable
                # findings, but keep FAIL/WARN as Observations so the
                # CoverageMatrix can credit the CIS item as executed.
                if status in ("PASS", "INFO", "MANUAL") and severity is Severity.INFO:
                    # Still emit so CoverageMatrix credits execution, but
                    # only if we haven't seen this test_number yet.
                    pass
                test_desc = _safe_str(
                    result.get("test_desc") or result.get("text") or test_number
                )
                asset_identity = f"{node_type or 'node'}:{test_number}"
                if asset_identity in seen:
                    continue
                seen.add(asset_identity)

                raw: dict[str, Any] = dict(result)
                # Normalize the id keys so downstream always finds them.
                raw.setdefault("id", control_id)
                raw.setdefault("control_id", control_id)
                raw.setdefault("test_id", test_number)
                raw["node_type"] = node_type

                observations.append(
                    Observation(
                        external_id=f"kube_bench:{node_type}:{test_number}:{idx}",
                        asset_identity=asset_identity,
                        source=source,
                        rule_id=test_number,
                        rule_version=_UPSTREAM_VERSION,
                        coverage_domain=CoverageDomain.CLOUD,
                        title=test_desc,
                        severity=severity,
                        confidence=0.9,
                        cwe=(),
                        cve=(),
                        owasp=(),
                        raw=raw,
                    )
                )
                idx += 1
    return tuple(observations)
