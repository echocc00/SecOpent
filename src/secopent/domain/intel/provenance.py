# src/secopent/domain/intel/provenance.py
"""Provenance record carried by every externally-sourced intel field.

`Provenance` answers "where did this fact come from, when did we fetch it, and
which version of the source did we read". It is the foundation of §10.7: the
platform MUST be able to attribute any given CVSS score, KEV flag, or detection
mapping to a specific source reading so that downstream policy can resolve
disagreements deterministically rather than by silent overwrite.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ..common.errors import DomainValidationError


@dataclass(frozen=True, slots=True)
class Provenance:
    """Source attribution for one externally-sourced intel reading.

    `fetched_at` MUST be timezone-aware. Naive datetimes are rejected at
    construction time so the canonical layer can serialise the value without
    ambiguity (see `secopent.domain.common.canonical`).
    """

    source: str
    fetched_at: datetime
    source_version: str

    def __post_init__(self) -> None:
        if not self.source:
            raise DomainValidationError("Provenance.source must be non-empty")
        if not self.source_version:
            raise DomainValidationError(
                "Provenance.source_version must be non-empty"
            )
        if self.fetched_at.tzinfo is None:
            raise DomainValidationError(
                "Provenance.fetched_at must be timezone-aware"
            )
