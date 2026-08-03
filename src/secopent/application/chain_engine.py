# src/secopent/application/chain_engine.py
"""ChainEngine: attack-chain hypotheses over confirmed findings (spec §9).

Hypothesis source #1 (this task): deterministic template matching. The
matcher extends chain_templates.match_template with link binding: matched
template links bind to concrete confirmed findings; unmatched trailing links
become pending verification tasks (the re-verification loop). Only
FindingStatus.VALIDATED findings participate - oracle is the sole confirmer.
"""
from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass

from ..domain.adapters.contracts import Severity
from ..domain.findings.attack_chain import (
    AttackChain,
    ChainLink,
    ChainStatus,
    composite_severity,
)
from ..domain.findings.chain_templates import AttackChainTemplate
from ..domain.findings.models import Finding, FindingStatus


@dataclass(frozen=True, slots=True)
class PendingVerificationTask:
    """补证投影：链中未确认环 → oracle 队列任务（响应式再规划触发源）."""

    key: str
    chain_id: str
    required_cwe: tuple[str, ...]
    asset_hint: str


class ChainEngine:
    """Generate and track attack-chain hypotheses."""

    def __init__(self, *, templates: tuple[AttackChainTemplate, ...]) -> None:
        self._templates = templates

    def hypothesize_from_findings(
        self, findings: Iterable[Finding]
    ) -> tuple[AttackChain, ...]:
        validated = [f for f in findings if f.status is FindingStatus.VALIDATED]
        chains: list[AttackChain] = []
        for template in self._templates:
            chain = self._match_template(template, validated)
            if chain is not None:
                chains.append(chain)
        return tuple(chains)

    def pending_verification_tasks(
        self, chains: Iterable[AttackChain]
    ) -> tuple[PendingVerificationTask, ...]:
        tasks: list[PendingVerificationTask] = []
        for chain in chains:
            tasks.extend(self._tasks_for(chain))
        return tuple(tasks)

    # -- internals ---------------------------------------------------------

    def _match_template(
        self, template: AttackChainTemplate, findings: list[Finding]
    ) -> AttackChain | None:
        links: list[ChainLink] = []
        position = 0
        matched_any = False
        for link_spec in template.links:
            bound: Finding | None = None
            for index in range(position, len(findings)):
                finding = findings[index]
                if not (set(link_spec.cwe_any) & set(finding.cwe)):
                    continue
                if link_spec.asset_pattern and link_spec.asset_pattern not in finding.asset:
                    continue
                bound = finding
                position = index + 1
                break
            if bound is not None:
                matched_any = True
                links.append(ChainLink(confirmed_finding_id=bound.id))
            else:
                links.append(
                    ChainLink(
                        pending_verification_key=f"pv-{uuid.uuid4().hex[:10]}",
                        note=f"requires CWE any of {link_spec.cwe_any}",
                    )
                )
        if not matched_any:
            return None
        chain_id = f"chain-{template.id}-{uuid.uuid4().hex[:8]}"
        all_confirmed = all(link.is_confirmed for link in links)
        # 首环起即部分确认 → PARTIALLY_VERIFIED，否则 HYPOTHESIS
        status = (
            ChainStatus.CONFIRMED
            if all_confirmed
            else (
                ChainStatus.PARTIALLY_VERIFIED
                if links[0].is_confirmed
                else ChainStatus.HYPOTHESIS
            )
        )
        severity = composite_severity(
            self._confirmed_severities(links, findings),
            asset_critical=False,  # Asset Graph 落地后接入资产价值
        )
        return AttackChain(
            id=chain_id,
            template_id=template.id,
            hypothesis_source="template",
            links=tuple(links),
            status=status,
            severity=severity,
        )

    @staticmethod
    def _confirmed_severities(
        links: list[ChainLink], findings: list[Finding]
    ) -> tuple[Severity, ...]:
        by_id = {f.id: f for f in findings}
        return tuple(
            by_id[link.confirmed_finding_id].severity
            for link in links
            if link.is_confirmed and link.confirmed_finding_id in by_id
        )

    def _tasks_for(
        self, chain: AttackChain
    ) -> tuple[PendingVerificationTask, ...]:
        template = next(
            (t for t in self._templates if t.id == chain.template_id), None
        )
        if template is None:
            return ()
        tasks: list[PendingVerificationTask] = []
        for link, spec in zip(chain.links, template.links, strict=True):
            if not link.is_confirmed:
                tasks.append(
                    PendingVerificationTask(
                        key=link.pending_verification_key,
                        chain_id=chain.id,
                        required_cwe=spec.cwe_any,
                        asset_hint=spec.asset_pattern,
                    )
                )
        return tuple(tasks)
