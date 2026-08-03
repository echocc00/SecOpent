# src/secopent/domain/findings/attack_chain.py
"""AttackChain: verified attack paths over confirmed findings (spec §9).

State machine: HYPOTHESIS -> PARTIALLY_VERIFIED -> CONFIRMED_CHAIN | REFUTED.
Only oracle-confirmed findings may fill links; pending links carry a
verification key pointing at an oracle-queue task. LLM/peer sources can
create chains but NEVER confirm them (LLM边界 extended to chain level).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..adapters.contracts import Severity
from ..common.errors import DomainValidationError


class ChainStatus(StrEnum):
    HYPOTHESIS = "hypothesis"
    PARTIALLY_VERIFIED = "partially_verified"
    CONFIRMED = "confirmed_chain"
    REFUTED = "refuted"


class ChainHypothesisSource(StrEnum):
    TEMPLATE = "template"        # 确定性模板匹配
    LLM = "llm_proposal"         # LLM 提议（仅提议）
    PEER = "peer_claim"          # peer agent 链声称（untrusted）


@dataclass(frozen=True, slots=True)
class ChainLink:
    """One link: either an oracle-confirmed finding or a pending verification."""

    confirmed_finding_id: str = ""
    pending_verification_key: str = ""
    note: str = ""

    def __post_init__(self) -> None:
        if not self.confirmed_finding_id and not self.pending_verification_key:
            raise DomainValidationError(
                "ChainLink needs confirmed_finding_id or pending_verification_key"
            )

    @property
    def is_confirmed(self) -> bool:
        return bool(self.confirmed_finding_id)


@dataclass(frozen=True, slots=True)
class AttackChain:
    id: str
    template_id: str  # 模板 id 或自由链的描述性 id
    hypothesis_source: str  # ChainHypothesisSource value
    links: tuple[ChainLink, ...]
    status: ChainStatus = ChainStatus.HYPOTHESIS
    severity: Severity = Severity.INFO

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError("AttackChain.id must be non-empty")
        if len(self.links) < 2:
            raise DomainValidationError("AttackChain needs at least 2 links")

    @property
    def all_links_confirmed(self) -> bool:
        return all(link.is_confirmed for link in self.links)


_SEVERITY_ORDER = (
    Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL,
)


def composite_severity(
    link_severities: tuple[Severity, ...], *, asset_critical: bool
) -> Severity:
    """Deterministic composite: max link severity, +1 level if the chain
    terminates on a critical asset (capped at CRITICAL)."""
    if not link_severities:
        return Severity.INFO
    top = max(link_severities, key=_SEVERITY_ORDER.index)
    if asset_critical:
        index = min(_SEVERITY_ORDER.index(top) + 1, len(_SEVERITY_ORDER) - 1)
        return _SEVERITY_ORDER[index]
    return top
