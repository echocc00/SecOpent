# src/secopent/domain/findings/models.py
"""Finding domain models (§13): the reportable, correlated unit.

A Finding is what gets reported - the result of correlating one or more
Observations that share a deterministic fingerprint. It carries the merged
CWE/CVE/OWASP attribution, the correlated observation/evidence ids, a severity,
and a lifecycle status.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..adapters.contracts import Severity
from ..common.errors import DomainValidationError


class FindingStatus(StrEnum):
    """Finding lifecycle states."""

    DRAFT = "draft"
    CANDIDATE = "candidate"
    VALIDATED = "validated"  # oracle-confirmed
    REPORTED = "reported"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


@dataclass(frozen=True, slots=True)
class Finding:
    """A correlated, reportable finding."""

    id: str
    fingerprint: str
    title: str
    asset: str
    severity: Severity
    cwe: tuple[str, ...] = ()
    cve: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    observation_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    status: FindingStatus = FindingStatus.DRAFT

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError("Finding.id must be non-empty")
        if not self.fingerprint:
            raise DomainValidationError("Finding.fingerprint must be non-empty")
        if not self.title:
            raise DomainValidationError("Finding.title must be non-empty")
        if not self.asset:
            raise DomainValidationError("Finding.asset must be non-empty")
