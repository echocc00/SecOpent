# src/secopent/infrastructure/peer_agents/strix_report.py
"""Parse Strix run artifacts into PeerAgentFindings (P2).

Source schema verified against usestrix/strix v1.4.x
(strix/tools/reporting/tool.py record fields, strix/report/sarif.py CWE
normalization notes). Parser is permissive on optional fields, strict on
JSON validity; entries without a usable target are dropped and counted.
"""
from __future__ import annotations

import json
from typing import Any

from ...domain.common.errors import DomainError
from ...domain.peer_agents.models import PeerAgentFinding

# poc_description summary length cap (Observation.raw does not carry full text).
_SUMMARY_MAX = 500


class StrixReportParseError(DomainError):
    """The Strix report artifact is not parseable JSON / not a list."""


def normalize_cwe(raw: str) -> str:
    """Normalize Strix CWE variants ('CWE-306' / 'cwe: 306' / '306')."""
    digits = "".join(ch for ch in str(raw) if ch.isdigit())
    if not digits:
        return ""
    return f"CWE-{int(digits)}"


def _entry_to_finding(
    entry: dict[str, Any], run_id: str, agent: str, index: int
) -> PeerAgentFinding | None:
    target = str(entry.get("target") or "").strip()
    title = str(entry.get("title") or "").strip()
    if not target or not title:
        return None
    cwe_raw = str(entry.get("cwe") or "")
    cwe_norm = normalize_cwe(cwe_raw)
    poc = str(entry.get("poc_description") or "").strip()
    return PeerAgentFinding(
        id=f"strix-{run_id}-{index}",
        run_id=run_id,
        agent_name=agent,
        title=title,
        asset=target,
        severity_hint=str(entry.get("severity") or "info"),
        cwe=(cwe_norm,) if cwe_norm else (),
        cve=(str(entry["cve"]),) if entry.get("cve") else (),
        payload_summary=poc[:_SUMMARY_MAX],
        raw_ref="",  # CAS ref filled by backend when collecting artifacts
    )


def parse_vulnerabilities_json(
    content: str,
    *,
    run_id: str,
    agent: str,
    with_problems: bool = False,
):
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise StrixReportParseError(f"invalid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise StrixReportParseError("vulnerabilities.json must be a list")
    findings: list[PeerAgentFinding] = []
    problems = 0
    for index, entry in enumerate(data):
        if not isinstance(entry, dict):
            problems += 1
            continue
        finding = _entry_to_finding(entry, run_id, agent, index)
        if finding is None:
            problems += 1
            continue
        findings.append(finding)
    if with_problems:
        return tuple(findings), problems
    return tuple(findings)
