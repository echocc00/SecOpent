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
from secopent.infrastructure.adapters.image_catalog import IMAGE_CATALOG

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
    _image = IMAGE_CATALOG.get("schemathesis")
    _digest = (
        _image.digest if _image and _image.digest
        else "sha256:schemathesis-" + _UPSTREAM_VERSION
    )
    return AdapterManifest(
        id="schemathesis",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="MIT",
        upstream=AdapterUpstream(
            name="schemathesis",
            url="https://github.com/schemathesis/schemathesis",
            version=_UPSTREAM_VERSION,
            digest=_digest,
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


def _extract_ndjson_events(text: str) -> list[dict[str, Any]]:
    """Extract JSON objects from mixed stdout (NDJSON + human-readable text).

    The real schemathesis CLI (``--report ndjson --report-ndjson-path
    /dev/stdout``) interleaves NDJSON event lines with human-readable progress
    output (banners, failure details, summary). We scan every line, skip
    non-JSON lines, and return the parsed JSON objects.
    """
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            events.append(obj)
    return events


def _failed_checks_from_events(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Extract failed checks from schemathesis NDJSON ScenarioFinished events.

    Each ``ScenarioFinished`` event has a ``recorder`` with ``label`` (e.g.
    ``"GET /anything"``) and ``checks`` (a dict of case_id -> list of check
    dicts). A failed check has ``status == "failure"`` with a ``name`` (e.g.
    ``"not_a_server_error"``) and optional ``failure_info``.

    Returns a flat list of ``{"check": ..., "method": ..., "path": ...,
    "message": ...}`` dicts consumable by the existing parse loop.
    """
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for event in events:
        sf = event.get("ScenarioFinished")
        if not isinstance(sf, dict):
            continue
        if sf.get("status") != "failure":
            continue
        recorder = sf.get("recorder")
        if not isinstance(recorder, dict):
            continue
        label = str(recorder.get("label") or "")
        # label is "METHOD /path" - split on first space.
        if " " in label:
            method, path = label.split(" ", 1)
        else:
            method, path = "GET", label or "/"
        checks = recorder.get("checks")
        if not isinstance(checks, dict):
            continue
        for _case_id, check_list in checks.items():
            if not isinstance(check_list, list):
                continue
            for check in check_list:
                if not isinstance(check, dict):
                    continue
                if check.get("status") != "failure":
                    continue
                check_name = str(check.get("name") or "unknown")
                key = (check_name, method, path)
                if key in seen:
                    continue
                seen.add(key)
                failure_info = check.get("failure_info") or {}
                message = ""
                if isinstance(failure_info, dict):
                    failure = failure_info.get("failure")
                    if isinstance(failure, dict):
                        message = str(failure.get("message") or "")
                results.append(
                    {
                        "check": check_name,
                        "method": method,
                        "path": path,
                        "message": message,
                        "status": sf.get("status"),
                    }
                )
    return results


def _load_results(stdout: str) -> list[dict[str, Any]]:
    """Parse Schemathesis output into a flat list of failed-check records.

    Handles three formats:
    1. JSON object with a ``results`` array (fixture format, legacy report).
    2. Pure NDJSON (one JSON object per line).
    3. The real schemathesis CLI stdout (mixed human-readable + NDJSON events
       from ``--report ndjson --report-ndjson-path /dev/stdout``): we extract
       ``ScenarioFinished`` events and flatten their failed checks.

    Returns ``[]`` on any parse failure.
    """
    if not stdout or not stdout.strip():
        return []
    text = stdout.strip()

    # Format 1: single JSON object with a ``results`` array.
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        obj = None
    if isinstance(obj, dict):
        results = obj.get("results")
        if isinstance(results, list):
            return [r for r in results if isinstance(r, dict)]
        # A flat result dict has check/method/path keys. A non-result dict
        # (e.g. a single NDJSON event like {"ScenarioFinished": ...}) must
        # fall through to the NDJSON path, not be treated as a result.
        if any(k in obj for k in ("check", "method", "path", "name")):
            return [obj]
        # Fall through to NDJSON extraction below.
    elif isinstance(obj, list):
        return [item for item in obj if isinstance(item, dict)]

    # Formats 2 + 3: NDJSON (possibly mixed with human-readable progress text).
    events = _extract_ndjson_events(text)
    if not events:
        return []

    # If the NDJSON is the legacy flat format (each line is already a result
    # dict with ``check`` / ``method`` / ``path`` keys), return as-is.
    flat_results = [
        e for e in events
        if "check" in e or "name" in e or "method" in e or "path" in e
    ]
    if flat_results:
        return flat_results

    # Real schemathesis NDJSON events: extract failed checks from
    # ScenarioFinished events.
    return _failed_checks_from_events(events)


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
