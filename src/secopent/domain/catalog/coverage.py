# src/secopent/domain/catalog/coverage.py
from __future__ import annotations

from dataclasses import dataclass, field

from ..common.canonical import canonical_digest
from ..common.errors import DomainValidationError


@dataclass(frozen=True, slots=True)
class CoverageMatrix:
    """Mapping of framework item ids -> covered test class ids.

    The matrix answers "what fraction of the framework's required items does
    the curated catalog cover". `coverage_rate()` returns covered_items /
    total_items where an item is covered when it has at least one mapped test
    class id.
    """

    version: str
    framework: str
    mappings: dict[str, tuple[str, ...]]
    total_items: int
    digest: str = field(default="")

    def __post_init__(self) -> None:
        if not self.version:
            raise DomainValidationError("CoverageMatrix.version must be non-empty")
        if not self.framework:
            raise DomainValidationError("CoverageMatrix.framework must be non-empty")
        if self.total_items < 1:
            raise DomainValidationError("CoverageMatrix.total_items must be >= 1")
        covered = sum(1 for v in self.mappings.values() if v)
        if covered > self.total_items:
            raise DomainValidationError(
                "CoverageMatrix covered items cannot exceed total_items"
            )
        if self.coverage_rate() < 0.0:
            raise DomainValidationError("CoverageMatrix coverage_rate cannot be negative")
        if not self.digest:
            object.__setattr__(
                self,
                "digest",
                canonical_digest(
                    {
                        "version": self.version,
                        "framework": self.framework,
                        "mappings": self.mappings,
                        "total_items": self.total_items,
                    }
                ),
            )

    def coverage_rate(self) -> float:
        """Return covered_items / total_items in [0.0, 1.0]."""

        covered = sum(1 for v in self.mappings.values() if v)
        return covered / self.total_items
