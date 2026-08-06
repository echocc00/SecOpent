# src/secopent/infrastructure/peer_agents/ptai_report.py
"""Permissive parser for ptai run artifacts (Phase 2.10; A4 spike).

ptai (0xSteph, MIT, https://pentestai.xyz) is an *autonomous* AI pentest
agent distributed as an MCP server + CLI (``ptai`` / ``pentest-ai``). Its
output format is **TBD** - it is agent-authored, not schema-stable. The
spike (sepcs/2026-07-27-a4-ptai-spike-findings.md) confirmed:

- ptai's top-level module is ``agents/`` (ad / api_security / browser /
  cloud / credential_tester ...), not a verification library;
- output is free-form markdown + optional JSON fragments;
- real schema collection happens on a Linux first-run (impacket /
  bloodhound / scapy are Linux-only deps; the Windows dev environment
  cannot ``pip install ptai`` with deps).

This parser is therefore **permissive by design** (same contract as
Shannon deliverables, P3):

- a JSON array of finding-like objects (``title`` + ``target``/``url``)
  yields findings;
- markdown blocks carrying a severity word + a URL yield findings;
- anything else is counted as a *problem* and never raises.

Never raises on content drift - problems are counted, findings survive.
"""
from __future__ import annotations

import json
import re
from typing import Any

from ...domain.peer_agents.models import PeerAgentFinding

_SEVERITY_WORDS = ("critical", "high", "medium", "low", "info")
_URL_PATTERN = re.compile(r"https?://[^\s)\]\"'>]+")
_CWE_PATTERN = re.compile(r"CWE-\d{1,4}", re.IGNORECASE)
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_HEADING_PATTERN = re.compile(r"^#{1,4}\s+", re.MULTILINE)
_SUMMARY_MAX = 500


def parse_ptai_artifacts(
    content: str, *, run_id: str, agent: str = "ptai"
) -> tuple[tuple[PeerAgentFinding, ...], int]:
    """Return (findings, problem_count) for one ptai artifact document.

    The document may be JSON (array of finding-like objects, or an object
    with a ``findings``/``vulnerabilities`` list) or free-form markdown.
    Never raises on parse failure - malformed JSON falls back to markdown
    block parsing; structureless non-empty content counts as one problem.
    """
    text = content.strip()
    if not text:
        return (), 0
    # Try JSON first (deterministic when present).
    findings, problems, consumed = _try_json(text, run_id=run_id, agent=agent)
    if consumed:
        return findings, problems
    # Fall back to permissive markdown block parsing.
    return _parse_markdown(text, run_id=run_id, agent=agent)


def _try_json(
    text: str, *, run_id: str, agent: str
) -> tuple[tuple[PeerAgentFinding, ...], int, bool]:
    """Attempt JSON parsing; return (findings, problems, consumed).

    ``consumed`` is True when the document was valid JSON (even if it held
    no findings) - the caller skips the markdown fallback in that case.
    """
    if not text.startswith(("{", "[")):
        return (), 0, False
    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError:
        return (), 0, False
    entries = _coerce_finding_list(data)
    findings: list[PeerAgentFinding] = []
    problems = 0
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            problems += 1
            continue
        finding = _json_entry_to_finding(entry, run_id=run_id, agent=agent, index=index)
        if finding is None:
            problems += 1
            continue
        findings.append(finding)
    return tuple(findings), problems, True


def _coerce_finding_list(data: Any) -> list[Any]:
    """Pull a list of finding-like entries out of a JSON document."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("findings", "vulnerabilities", "results", "issues"):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


def _json_entry_to_finding(
    entry: dict[str, Any], *, run_id: str, agent: str, index: int
) -> PeerAgentFinding | None:
    """Build a finding from a JSON object; None when it lacks title+asset."""
    title = str(entry.get("title") or entry.get("name") or "").strip()
    asset = str(
        entry.get("target")
        or entry.get("url")
        or entry.get("asset")
        or entry.get("host")
        or ""
    ).strip()
    if not title or not asset:
        return None
    severity = str(entry.get("severity") or entry.get("risk") or "info").strip().lower()
    if severity not in _SEVERITY_WORDS:
        severity = "info"
    cwes = tuple(sorted({
        _norm_cwe(str(c))
        for c in _as_list(entry.get("cwe"))
        if _norm_cwe(str(c))
    }))
    cves = tuple(sorted({
        str(c).upper()
        for c in _as_list(entry.get("cve"))
        if _CVE_PATTERN.fullmatch(str(c))
    }))
    poc = str(entry.get("poc") or entry.get("evidence") or entry.get("description") or "").strip()
    return PeerAgentFinding(
        id=f"{agent}-{run_id}-{index}",
        run_id=run_id,
        agent_name=agent,
        title=title[:200],
        asset=asset,
        severity_hint=severity,
        cwe=cwes,
        cve=cves,
        payload_summary=poc[:_SUMMARY_MAX],
        raw_ref="",
    )


def _parse_markdown(
    text: str, *, run_id: str, agent: str
) -> tuple[tuple[PeerAgentFinding, ...], int]:
    """Permissive markdown block parser (Shannon-style)."""
    blocks = _split_blocks(text)
    findings: list[PeerAgentFinding] = []
    problems = 0
    for index, block in enumerate(blocks):
        lowered = block.lower()
        severity = next((w for w in _SEVERITY_WORDS if w in lowered), None)
        if severity is None:
            continue
        urls = _URL_PATTERN.findall(block)
        if not urls:
            problems += 1
            continue
        cwes = tuple(sorted({m.upper() for m in _CWE_PATTERN.findall(block)}))
        cves = tuple(sorted({m.upper() for m in _CVE_PATTERN.findall(block)}))
        findings.append(PeerAgentFinding(
            id=f"{agent}-{run_id}-{index}",
            run_id=run_id,
            agent_name=agent,
            title=_block_title(block),
            asset=urls[0],
            severity_hint=severity,
            cwe=cwes,
            cve=cves,
            payload_summary=_code_summary(block),
            raw_ref="",
        ))
    if not findings and not problems:
        problems = 1  # content present but no structure
    return tuple(findings), problems


def _split_blocks(text: str) -> tuple[str, ...]:
    """Split into heading-delimited blocks; fall back to paragraph blocks."""
    if _HEADING_PATTERN.search(text):
        parts = re.split(r"(?=^#{1,4}\s+)", text, flags=re.MULTILINE)
        return tuple(p.strip() for p in parts if p.strip())
    return tuple(p.strip() for p in re.split(r"\n\s*\n", text) if p.strip())


def _block_title(block: str) -> str:
    """First non-empty heading or first non-empty line, truncated."""
    for line in block.splitlines():
        stripped = line.lstrip("#").strip()
        if stripped:
            return stripped[:200]
    return "ptai finding"


def _code_summary(block: str) -> str:
    """First fenced-code-block body (truncated); empty when none."""
    match = _CODE_FENCE.search(block)
    if match is None:
        return ""
    return match.group(1).strip()[:_SUMMARY_MAX]


_CODE_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)


def _norm_cwe(raw: str) -> str:
    digits = "".join(ch for ch in raw if ch.isdigit())
    if not digits:
        return ""
    return f"CWE-{int(digits)}"


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list | tuple):
        return list(value)
    return [value]
