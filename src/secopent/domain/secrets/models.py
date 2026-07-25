# src/secopent/domain/secrets/models.py
"""Secret metadata (§12): only a reference, never the plaintext.

The domain models a secret purely by its ``secret_ref`` + name + timestamps.
The plaintext value lives only in the (infrastructure) SecretBackend, is resolved
transiently at execution time, and never appears in the domain model, prompts,
logs, evidence, or reports.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ..common.errors import DomainValidationError


@dataclass(frozen=True, slots=True)
class SecretMetadata:
    """A secret handle - reference only, deliberately no plaintext value."""

    secret_ref: str
    name: str
    created_at: datetime

    def __post_init__(self) -> None:
        if not self.secret_ref:
            raise DomainValidationError("SecretMetadata.secret_ref must be non-empty")
        if not self.name:
            raise DomainValidationError("SecretMetadata.name must be non-empty")
