# src/secopent/infrastructure/peer_agents/shannon_deliverables.py
"""Permissive parser for Shannon deliverables markdown (P3).

Shannon's agents author free-form markdown deliverables (no schema
guarantee). Parser contract: heading-delimited blocks carrying a severity
word + a URL become findings; blocks with a severity word but no URL count
as problems; an entirely structureless non-empty document is one problem.
Never raises on content drift - problems are counted, findings survive.
"""
from __future__ import annotations

import re

from ...domain.peer_agents.models import PeerAgentFinding

_SEVERITY_WORDS = ("critical", "high", "medium", "low", "info")
_URL_PATTERN = re.compile(r"https?://[^\s)\]\"'>]+")
_CWE_PATTERN = re.compile(r"CWE-\d{1,4}")
_HEADING_PATTERN = re.compile(r"^#{1,4}\s+", re.MULTILINE)
_CODE_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_SUMMARY_MAX = 500


def parse_deliverable_markdown(
    content: str, *, run_id: str, agent: str, vuln_class: str
) -> tuple[tuple[PeerAgentFinding, ...], int]:
    """Return (findings, problem_count) for one deliverable document."""
    text = content.strip()
    if not text:
        return (), 0
    blocks = _split_blocks(text)
    findings: list[PeerAgentFinding] = []
    problems = 0
    for index, block in enumerate(blocks):
        lowered = block.lower()
        severity = next((w for w in _SEVERITY_WORDS if w in lowered), None)
        if severity is None:
            continue  # 非 finding 块（概述/方法说明等）
        urls = _URL_PATTERN.findall(block)
        if not urls:
            problems += 1
            continue
        cwes = tuple(sorted(set(_CWE_PATTERN.findall(block))))
        findings.append(PeerAgentFinding(
            id=f"shannon-{run_id}-{vuln_class}-{index}",
            run_id=run_id,
            agent_name=agent,
            title=_block_title(block),
            asset=urls[0],
            severity_hint=severity,
            cwe=cwes,
            payload_summary=_code_summary(block),
            raw_ref="",
        ))
    if not findings and not problems:
        problems = 1  # 有内容但完全无结构
    return tuple(findings), problems


def _split_blocks(text: str) -> tuple[str, ...]:
    positions = [m.start() for m in _HEADING_PATTERN.finditer(text)]
    if not positions:
        return (text,)
    blocks: list[str] = []
    for start, end in zip(positions, positions[1:] + [len(text)]):
        chunk = text[start:end].strip()
        if chunk:
            blocks.append(chunk)
    return tuple(blocks)


def _block_title(block: str) -> str:
    first_line = block.splitlines()[0]
    return _HEADING_PATTERN.sub("", first_line, count=1).strip() or "untitled"


def _code_summary(block: str) -> str:
    match = _CODE_FENCE.search(block)
    if match:
        return match.group(1).strip()[:_SUMMARY_MAX]
    url_match = _URL_PATTERN.search(block)
    if url_match:
        after = block[url_match.end():].strip().splitlines()
        if after:
            return after[0][:_SUMMARY_MAX]
    return ""
