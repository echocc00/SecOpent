# src/secopent/domain/catalog/models.py
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ..common.canonical import canonical_digest
from ..common.errors import DomainValidationError
from ..policy.models import RiskClass


class AssetType(StrEnum):
    """Catalog of asset types addressed by required test classes."""

    WEB_APP = "web_app"
    API = "api"
    IP_PORT = "ip_port"
    CLOUD_ACCOUNT = "cloud_account"
    CONTAINER_K8S = "container_k8s"


@dataclass(frozen=True, slots=True)
class RequiredTestClass:
    """A curated test class required for one or more asset types.

    `cwe` and `owasp` are tuples so the class can map to multiple framework
    categories (used to feed CoverageMatrix mapping).
    """

    id: str
    cwe: tuple[str, ...]
    owasp: tuple[str, ...]
    risk: RiskClass

    def __post_init__(self) -> None:
        if not self.id:
            raise DomainValidationError("RequiredTestClass.id must be non-empty")


@dataclass(frozen=True, slots=True)
class TestCatalog:
    """Curated, versioned mapping of asset type -> required test classes.

    The catalog is the platform's curated "what to test" knowledge layer. It is
    pinned per Assessment via its `digest` so coverage decisions remain
    reproducible across catalog updates.
    """

    # Pytest would otherwise try to collect this dataclass as a test class
    # because of its `Test*` prefix.
    __test__ = False

    version: str
    mappings: dict[AssetType, tuple[RequiredTestClass, ...]]
    digest: str = field(default="")

    def __post_init__(self) -> None:
        if not self.version:
            raise DomainValidationError("TestCatalog.version must be non-empty")
        if not self.digest:
            object.__setattr__(
                self,
                "digest",
                canonical_digest(
                    {
                        "version": self.version,
                        "mappings": self.mappings,
                    }
                ),
            )

    def required_for(self, asset_type: AssetType) -> tuple[RequiredTestClass, ...]:
        """Return the required test classes for the given asset type.

        Unknown asset types return an empty tuple (caller decides whether to
        fail or accept zero-coverage).
        """

        return self.mappings.get(asset_type, ())
