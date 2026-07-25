"""RESTler adapter: stateful API sequence testing (§8.2, decision 23, active).

RESTler is a stateful REST API fuzzer that generates sequences of API requests
from an OpenAPI spec and probes for sequence bugs by mutating the request
order. Decision 23 adopted RESTler (alongside Schemathesis) for the Web/API
domain because pure property-based testing misses state-dependent bugs that
only surface when endpoints are called in a specific order.

RESTler emits a `bugs.json` file containing the bug classes it found:

- `skip_step` - a sequence bug revealed by skipping a step
- `out_of_order` - a bug revealed by reordering requests
- `replay` - a bug revealed by replaying a request

The parser surfaces `test_class` in `raw` so the CoverageMatrix can attribute
coverage to the corresponding decision-23 sequence-testing class.
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

_PARSER_ENTRYPOINT = "secopent_adapters.restler:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "9.2.0"

# RESTler bug_class -> severity. Sequence bugs that surface as 5xx or auth
# bypass are HIGH; resource-leak replays are MEDIUM.
_BUG_SEVERITY: dict[str, Severity] = {
    "skip_step": Severity.HIGH,
    "out_of_order": Severity.HIGH,
    "replay": Severity.MEDIUM,
}


def manifest() -> AdapterManifest:
    """Return the RESTler AdapterManifest (active, decision 23)."""
    return AdapterManifest(
        id="restler",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="MIT",
        upstream=AdapterUpstream(
            name="restler",
            url="https://github.com/microsoft/restler-fuzzer",
            version=_UPSTREAM_VERSION,
            digest="sha256:restler-" + _UPSTREAM_VERSION,
        ),
        risk_class=RiskClass.ACTIVE,
        coverage_domain=(CoverageDomain.WEB,),
        input_schema="schema://restler/input.json",
        output_schema="schema://restler/output.json",
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


def _flatten_bugs(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten dict records into a flat list of bug records.

    Each record may either BE a bug (has `bug_class` / `test_class` /
    `endpoint`) or CONTAIN bugs under a `bugs` key. We expand containers and
    return only bug-shaped dicts.
    """
    out: list[dict[str, Any]] = []
    for record in records:
        inner = record.get("bugs")
        if isinstance(inner, list):
            out.extend(b for b in inner if isinstance(b, dict))
        else:
            out.append(record)
    return out


def _load_bugs(stdout: str) -> list[dict[str, Any]]:
    """Parse RESTler bugs.json (either JSON array or NDJSON).

    Returns `[]` on any parse failure. Flattens `{"bugs": [...]}` containers
    into a flat list of bug records.
    """
    if not stdout or not stdout.strip():
        return []
    text = stdout.strip()
    # NDJSON first.
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return []
        if isinstance(obj, dict):
            records.append(obj)
        elif isinstance(obj, list):
            records.extend(item for item in obj if isinstance(item, dict))
    if records:
        return _flatten_bugs(records)
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(obj, dict):
        return _flatten_bugs([obj])
    if isinstance(obj, list):
        return _flatten_bugs([item for item in obj if isinstance(item, dict)])
    return []


def parse(
    *, stdout: str, source: AdapterSource, artifacts: dict[str, bytes]
) -> tuple[Observation, ...]:
    """Parse RESTler bugs.json into Observation records.

    Each bug becomes one Observation with `coverage_domain=web`, `test_class`
    in raw (one of skip_step / out_of_order / replay). The rule_id carries
    the bug_class so downstream correlation can group by class.
    """
    records = _load_bugs(stdout)
    if not records:
        return ()
    observations: list[Observation] = []
    seen: set[tuple[str, str]] = set()
    for idx, record in enumerate(records):
        bug_class = (
            record.get("bug_class")
            or record.get("test_class")
            or record.get("type")
            or "unknown"
        )
        bug_class = str(bug_class).lower().replace("-", "_")
        # The sequence endpoint that triggered the bug.
        endpoint = (
            record.get("endpoint")
            or record.get("request")
            or record.get("url")
            or record.get("method")
            or ""
        )
        key = (bug_class, str(endpoint))
        if not endpoint or key in seen:
            continue
        seen.add(key)
        severity = _BUG_SEVERITY.get(bug_class, Severity.MEDIUM)
        title = f"restler sequence bug: {bug_class} at {endpoint}"
        raw = dict(record)
        # Surface test_class explicitly so CoverageMatrix attribution is
        # deterministic (decision 23).
        raw["test_class"] = bug_class
        observations.append(
            Observation(
                external_id=f"restler:{bug_class}:{endpoint}:{idx}",
                asset_identity=str(endpoint),
                source=source,
                rule_id=f"restler.{bug_class}",
                rule_version=_UPSTREAM_VERSION,
                coverage_domain=CoverageDomain.WEB,
                title=title,
                severity=severity,
                confidence=0.8,
                cwe=(),
                cve=(),
                owasp=("A04:2021",),  # Insecure Design - sequence bugs are design-level
                raw=raw,
            )
        )
    return tuple(observations)
