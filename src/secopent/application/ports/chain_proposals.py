# src/secopent/application/ports/chain_proposals.py
"""Proposal ports for chain hypotheses (spec §9 sources ②③).

Both sources PROPOSE only. A proposed link counts as confirmed iff it
references a Finding whose status is VALIDATED (oracle-confirmed); any
other claim stays pending. Ports are Protocols so tests inject fakes and
the real LLM proposal generator (P2b 后续/M4 LLM 面）与 peer 解析器按接线接入。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ...domain.findings.models import Finding


@dataclass(frozen=True, slots=True)
class ChainProposal:
    proposer: str            # "llm:<model>" 或 "peer:strix"
    template_hint: str       # 模板 id 或自由描述 id
    finding_ids: tuple[str, ...]  # 声称的环顺序（可含未确认引用）


@runtime_checkable
class ChainProposalSource(Protocol):
    def propose(
        self, findings: tuple[Finding, ...]
    ) -> tuple[ChainProposal, ...]: ...
