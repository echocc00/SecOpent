"""Shared parser utilities for asset-mapping adapters.

`safe_jsonl_load` parses newline-delimited JSON (the format ProjectDiscovery
tools emit with `-json`/`-jsonl`). On any parse failure it returns an empty
list - parsers translate that into zero Observations rather than crashing,
so a malformed tool stream never takes down the runner.
"""
from __future__ import annotations

import json
from typing import Any


def safe_jsonl_load(stdout: str) -> list[dict[str, Any]]:
    """Parse JSONL/NDJSON, tolerating blank lines; empty list on failure.

    Some ProjectDiscovery tools also wrap output as a single JSON array, so
    we fall back to `json.loads` if newline-splitting yields no records.
    Returns `[]` on any unrecoverable parse error.
    """
    if not stdout or not stdout.strip():
        return []
    records: list[dict[str, Any]] = []
    for line in stdout.splitlines():
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
            for item in obj:
                if isinstance(item, dict):
                    records.append(item)
    if records:
        return records
    # Fall back: whole stdout may be a single JSON array or object.
    try:
        obj = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(obj, dict):
        return [obj]
    if isinstance(obj, list):
        return [item for item in obj if isinstance(item, dict)]
    return []
