"""Schemathesis adapter: API property-based boundary testing (§8.2, decision 23).

Schemathesis is a property-based API tester that generates inputs from an
OpenAPI spec and pushes the API past its declared boundaries (越界测试).
Decision 23 adopted Schemathesis (alongside RESTler) for the Web/API domain
because stateless boundary testing catches input-validation defects that
stateful sequence testing (RESTler) does not.

Schemathesis emits a JSON report with a list of `results`, each representing
a failed check (`check` field) against an `endpoint` / `method`. The parser
tags every Observation with `test_class="boundary"` so CoverageMatrix can
attribute the boundary-testing coverage item.
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

_PARSER_ENTRYPOINT = "secopent_adapters.schemathesis:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "3.36.4"

# Schemathesis check -> severity. The default `not_a_server_error` check
# (5xx under valid inputs) is HIGH; `status_code_conformance` /
# `content_type_conformance` are MEDIUM.
_CHECK_SEVERITY: dict[str, Severity] = {
    "not_a_server_error": Severity.HIGH,
    "status_code_conformance": Severity.MEDIUM,
    "content_type_conformance": Severity.MEDIUM,
    "response_schema_conformance": Severity.MEDIUM,
    "negative_data_rejection": Severity.HIGH,
    "ensure_check_ast_removal": Severity.LOW,
}


def manifest() -> AdapterManifest:
    """Return the Schemathesis AdapterManifest (active, decision 23)."""
    return AdapterManifest(
        id="schemathesis",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="MIT",
        upstream=AdapterUpstream(
            name="schemathesis",
            url="https://github.com/schemathesis/schemathesis",
            version=_UPSTREAM_VERSION,
            digest="sha256:schemathesis-" + _UPSTREAM_VERSION,
        ),
        risk_class=RiskClass.ACTIVE,
        coverage_domain=(CoverageDomain.WEB,),
        input_schema="schema://schemathesis/input.json",
        output_schema="schema://schemathesis/output.json",
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


def _load_results(stdout: str) -> list[dict[str, Any]]:
    """Parse Schemathesis JSON report.

    The report is a JSON object with a `results` array (or top-level array).
    Returns `[]` on any parse failure.
    """
    if not stdout or not stdout.strip():
        return []
    text = stdout.strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        # Maybe NDJSON.
        records: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                return []
            if isinstance(item, dict):
                records.append(item)
        return records
    if isinstance(obj, dict):
        results = obj.get("results")
        if isinstance(results, list):
            return [r for r in results if isinstance(r, dict)]
        return [obj]
    if isinstance(obj, list):
        return [item for item in obj if isinstance(item, dict)]
    return []


def parse(
    *, stdout: str, source: AdapterSource, artifacts: dict[str, bytes]
) -> tuple[Observation, ...]:
    """Parse Schemathesis JSON report into Observation records.

    Each failed check becomes one Observation with `coverage_domain=web`,
    `test_class="boundary"` in raw (decision 23). Severity is derived from
    the Schemathesis check name.
    """
    records = _load_results(stdout)
    if not records:
        return ()
    observations: list[Observation] = []
    seen: set[tuple[str, str, str]] = set()
    for idx, record in enumerate(records):
        check = record.get("check") or record.get("name") or "unknown"
        method = record.get("method") or record.get("verb") or "GET"
        path = record.get("path") or record.get("endpoint") or record.get("url") or "/"
        endpoint = f"{method} {path}"
        key = (str(check), method, path)
        if key in seen:
            continue
        seen.add(key)
        check_str = str(check)
        severity = _CHECK_SEVERITY.get(check_str, Severity.MEDIUM)
        title = f"schemathesis boundary: {check_str} failed on {endpoint}"
        raw = dict(record)
        # Surface test_class explicitly for CoverageMatrix attribution.
        raw["test_class"] = "boundary"
        observations.append(
            Observation(
                external_id=f"schemathesis:{check_str}:{method}:{path}:{idx}",
                asset_identity=endpoint,
                source=source,
                rule_id=f"schemathesis.{check_str}",
                rule_version=_UPSTREAM_VERSION,
                coverage_domain=CoverageDomain.WEB,
                title=title,
                severity=severity,
                confidence=0.85,
                cwe=(),
                cve=(),
                owasp=("A04:2021",),  # Insecure Design - boundary gaps are design-level
                raw=raw,
            )
        )
    return tuple(observations)
