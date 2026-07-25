# src/secopent/domain/evidence/models.py
"""Evidence domain models (§13): three-layer, content-addressed, redactable.

Evidence is captured in three layers:

- **RAW** - verbatim tool output, never mutated.
- **REDACTED** - secrets/PII masked; a *new* object linked to the RAW via
  ``source_id`` and independently signed.
- **SUMMARY** - a human-readable digest, also derived from the RAW.

Each layer is content-addressed by sha256 so redaction never overwrites the RAW
evidence (the audit trail stays intact). ``SecretOrigin`` distinguishes *our*
secrets (canary tokens / own credentials - always masked) from *target* secrets
(credentials discovered on the target - masked in shared output but flagged as
evidence).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..common.errors import DomainValidationError


class EvidenceLayer(StrEnum):
    """The three evidence layers."""

    RAW = "raw"
    REDACTED = "redacted"
    SUMMARY = "summary"


class SecretOrigin(StrEnum):
    """Whose secret a redacted span is."""

    OURS = "ours"  # our canary / own credential - always mask
    TARGET = "target"  # target credential found - mask in shared output, flag as evidence


@dataclass(frozen=True, slots=True)
class Redaction:
    """A single redacted span (the matched value itself is never stored)."""

    kind: str
    origin: SecretOrigin

    def __post_init__(self) -> None:
        if not self.kind:
            raise DomainValidationError("Redaction.kind must be non-empty")


@dataclass(frozen=True, slots=True)
class RedactionResult:
    """Outcome of running the RedactionEngine over a text blob."""

    redacted_text: str
    redactions: tuple[Redaction, ...]

    @property
    def count(self) -> int:
        return len(self.redactions)

    def count_by_origin(self, origin: SecretOrigin) -> int:
        return sum(1 for r in self.redactions if r.origin is origin)


@dataclass(frozen=True, slots=True)
class Evidence:
    """A content-addressed evidence object in one layer.

    ``sha256`` is the content digest (``sha256:<hex>``); ``storage_uri`` is the
    CAS location. For REDACTED/SUMMARY layers, ``source_id`` links back to the
    RAW evidence this was derived from and ``signature`` is an independent
    signature over the derived content.
    """

    id: str
    layer: EvidenceLayer
    sha256: str
    storage_uri: str
    source_id: str = ""
    signature: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError("Evidence.id must be non-empty")
        if not self.sha256.startswith("sha256:"):
            raise DomainValidationError("Evidence.sha256 must be a sha256: digest")
        if not self.storage_uri:
            raise DomainValidationError("Evidence.storage_uri must be non-empty")
