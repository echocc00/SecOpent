# src/secopent/domain/peer_agents/models.py
"""Peer agent domain models (integration spec §4-§5, extends ADR-014/A4).

A peer agent is an external autonomous pentesting agent (Strix, Shannon, ...)
treated as a LOW-TRUST DISCOVERY SOURCE - on par with tool adapters. Its
findings are untrusted Observations-in-waiting: they must pass the scope
re-check, the catalog gate, and oracle N/N verification exactly like tool
output. The LLM边界 holds: peer agents (LLM-driven) never mark anything
Confirmed - only the OracleEngine does.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from ..common.errors import DomainError, DomainValidationError


class PeerAgentNotRegistered(DomainError):
    """The peer agent name is not in the deterministic registry."""


class PeerAgentTrustDenied(DomainError):
    """The peer agent's trust level does not permit execution."""


class PeerRunScopeViolation(DomainError):
    """A launch target (or reported finding asset) is outside the scope."""


class PeerRunBudgetExceeded(DomainError):
    """The run exceeded its wall-clock or cost budget."""


class PeerAgentTrustLevel(StrEnum):
    """Trust levels for external agents (A4 spike precedent)."""

    ADOPTED_EXTERNAL = "adopted_external_agent"
    UNTRUSTED = "untrusted"


class PeerRunStatus(StrEnum):
    """Peer run lifecycle states."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    BUDGET_EXCEEDED = "budget_exceeded"
    STOPPED = "stopped"
    FAILED = "failed"


class RejectionReason(StrEnum):
    """Why a peer finding was rejected at the normalization gate."""

    OUT_OF_SCOPE = "out_of_scope"
    OUT_OF_CATALOG = "out_of_catalog"
    PARSE_ERROR = "parse_error"


@dataclass(frozen=True, slots=True)
class PeerAgentBudget:
    """Per-run budget caps (spec §4: Permit 增加墙钟时长 + LLM 成本类)."""

    max_wall_seconds: int
    max_cost_units: float

    def __post_init__(self) -> None:
        if self.max_wall_seconds < 0:
            raise DomainValidationError(
                "PeerAgentBudget.max_wall_seconds must be >= 0"
            )
        if self.max_cost_units < 0:
            raise DomainValidationError(
                "PeerAgentBudget.max_cost_units must be >= 0"
            )


@dataclass(frozen=True, slots=True)
class PeerAgentDescriptor:
    """Registered identity of an allowed peer agent (curated, deterministic).

    ``image_digest`` is empty until the image is pinned (same policy as
    ``infrastructure/adapters/image_catalog.py``).
    """

    name: str
    version: str
    license: str
    trust_level: PeerAgentTrustLevel
    capabilities: tuple[str, ...]
    cost_class: str
    default_budget: PeerAgentBudget
    image_digest: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            raise DomainValidationError(
                "PeerAgentDescriptor.name must be non-empty"
            )
        if not self.version:
            raise DomainValidationError(
                "PeerAgentDescriptor.version must be non-empty"
            )


@dataclass(frozen=True, slots=True)
class PeerAgentRun:
    """One execution of a peer agent against in-scope targets."""

    id: str
    agent_name: str
    agent_version: str
    assessment_id: str
    targets: tuple[str, ...]
    budget: PeerAgentBudget
    permit_id: str
    status: PeerRunStatus = PeerRunStatus.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError("PeerAgentRun.id must be non-empty")
        if not self.targets:
            raise DomainValidationError(
                "PeerAgentRun.targets must be non-empty"
            )


@dataclass(frozen=True, slots=True)
class PeerAgentFinding:
    """An UNTRUSTED finding reported by a peer agent (pre-normalization).

    ``severity_hint`` is the agent's free-text severity; normalization maps it
    deterministically onto ``Severity`` (unknown hints downgrade to INFO and
    are recorded in the Observation's ``raw``).
    """

    id: str
    run_id: str
    agent_name: str
    title: str
    asset: str
    severity_hint: str
    cwe: tuple[str, ...] = ()
    cve: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    payload_summary: str = ""
    raw_ref: str = ""  # cas:// URI of the raw report fragment

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError(
                "PeerAgentFinding.id must be non-empty"
            )
        if not self.run_id:
            raise DomainValidationError(
                "PeerAgentFinding.run_id must be non-empty"
            )
        if not self.title:
            raise DomainValidationError(
                "PeerAgentFinding.title must be non-empty"
            )
        if not self.asset:
            raise DomainValidationError(
                "PeerAgentFinding.asset must be non-empty"
            )


@dataclass(frozen=True, slots=True)
class RejectedFinding:
    """A rejected peer finding, retained for audit (never silently dropped)."""

    finding: PeerAgentFinding
    reason: RejectionReason
    detail: str = ""


@dataclass(frozen=True, slots=True)
class PeerAgentReport:
    """Parsed output of one peer run (wall/cost are self-reported by the
    backend; the budget post-check treats them as audit data)."""

    run_id: str
    findings: tuple[PeerAgentFinding, ...]
    wall_seconds: float
    cost_units: float
    exit_code: int
