# src/secopent/domain/findings/chain_templates.py
"""AttackChainTemplate: curated attack-chain link patterns (spec §9, P1a③).

Deterministic curation content: a template is an ordered list of link specs
(matched by CWE family and optional asset pattern). P2b's ChainEngine uses
them as one of three hypothesis sources. Templates never confirm anything -
every link must still be backed by an oracle-confirmed finding (LLM boundary).
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..common.errors import DomainValidationError


@dataclass(frozen=True, slots=True)
class ChainLinkSpec:
    """One link in a chain template: CWE family (+ optional asset pattern)."""

    cwe_any: tuple[str, ...]
    asset_pattern: str = ""  # substring match on finding asset ("" = any)


@dataclass(frozen=True, slots=True)
class AttackChainTemplate:
    """An ordered chain of link specs representing a known attack pattern."""

    id: str
    name: str
    links: tuple[ChainLinkSpec, ...]
    tactic: str  # ATT&CK tactic label (curation metadata)

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError(
                "AttackChainTemplate.id must be non-empty"
            )
        if len(self.links) < 2:
            raise DomainValidationError(
                "AttackChainTemplate needs at least 2 links"
            )


def match_template(
    template: AttackChainTemplate,
    findings: Sequence[tuple[tuple[str, ...], str]],
) -> bool:
    """Order-preserving subsequence match of link specs over findings.

    ``findings`` items are ``(cwe_tuple, asset)`` projections of confirmed
    findings. Each link spec must match a finding AFTER the previous link's
    match position; CWE match = set intersection; asset_pattern = substring.
    """
    position = 0
    for link in template.links:
        matched = False
        for index in range(position, len(findings)):
            cwes, asset = findings[index]
            if not (set(link.cwe_any) & set(cwes)):
                continue
            if link.asset_pattern and link.asset_pattern not in asset:
                continue
            position = index + 1
            matched = True
            break
        if not matched:
            return False
    return True


def default_chain_templates() -> tuple[AttackChainTemplate, ...]:
    """First curated batch (spec §9 chain template examples + industry chains)."""
    return (
        AttackChainTemplate(
            id="ssrf-to-cloud-creds",
            name="SSRF -> cloud metadata -> credential leak",
            links=(
                ChainLinkSpec(cwe_any=("CWE-918",)),
                ChainLinkSpec(
                    cwe_any=("CWE-918", "CWE-200"),
                    asset_pattern="169.254.169.254",
                ),
                ChainLinkSpec(cwe_any=("CWE-522", "CWE-312", "CWE-200")),
            ),
            tactic="credential-access",
        ),
        AttackChainTemplate(
            id="auth-bypass-plus-idor",
            name="Authentication bypass -> IDOR horizontal escalation",
            links=(
                ChainLinkSpec(cwe_any=("CWE-287", "CWE-288")),
                ChainLinkSpec(cwe_any=("CWE-639", "CWE-284")),
            ),
            tactic="privilege-escalation",
        ),
        AttackChainTemplate(
            id="sqli-to-credential-theft",
            name="SQL injection -> credential dump -> credential stuffing",
            links=(
                ChainLinkSpec(cwe_any=("CWE-89",)),
                ChainLinkSpec(cwe_any=("CWE-256", "CWE-312", "CWE-200")),
                ChainLinkSpec(cwe_any=("CWE-798", "CWE-640")),
            ),
            tactic="credential-access",
        ),
        AttackChainTemplate(
            id="xss-to-session-theft",
            name="Stored XSS -> session token theft -> account takeover",
            links=(
                ChainLinkSpec(cwe_any=("CWE-79",)),
                ChainLinkSpec(cwe_any=("CWE-384", "CWE-614")),
                ChainLinkSpec(cwe_any=("CWE-287",)),
            ),
            tactic="collection",
        ),
        AttackChainTemplate(
            id="weak-creds-to-admin-takeover",
            name="Weak credentials -> admin panel -> privilege abuse",
            links=(
                ChainLinkSpec(cwe_any=("CWE-521", "CWE-798")),
                ChainLinkSpec(cwe_any=("CWE-269", "CWE-285")),
            ),
            tactic="privilege-escalation",
        ),
    )
