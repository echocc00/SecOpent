# src/secopent/infrastructure/repositories/sqlalchemy_catalog.py
"""SqlAlchemy repositories for TestCatalog and CoverageMatrix.

Follows the M0 ``sqlalchemy_core.py`` pattern: ``_to_*`` / ``_from_*``
converters between domain dataclasses and ORM rows, Session-based API,
JSON columns for nested structures (mappings dict).
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...domain.catalog.coverage import CoverageMatrix
from ...domain.catalog.models import (
    AssetType,
    RequiredTestClass,
    TestCatalog,
)
from ...domain.policy.models import RiskClass
from ..db.catalog_models import CoreCoverageMatrix, CoreTestCatalog


def _required_class_to_dict(cls_: RequiredTestClass) -> dict[str, Any]:
    return {
        "id": cls_.id,
        "cwe": list(cls_.cwe),
        "owasp": list(cls_.owasp),
        "risk": cls_.risk.value,
    }


def _required_class_from_dict(data: dict[str, Any]) -> RequiredTestClass:
    return RequiredTestClass(
        id=data["id"],
        cwe=tuple(data["cwe"]),
        owasp=tuple(data["owasp"]),
        risk=RiskClass(data["risk"]),
    )


def _catalog_to_dict(catalog: TestCatalog) -> dict[str, Any]:
    return {
        asset_type.value: [_required_class_to_dict(c) for c in classes]
        for asset_type, classes in catalog.mappings.items()
    }


def _catalog_from_dict(data: dict[str, Any]) -> dict[AssetType, tuple[RequiredTestClass, ...]]:
    return {
        AssetType(key): tuple(_required_class_from_dict(c) for c in classes)
        for key, classes in data.items()
    }


def _to_catalog(row: CoreTestCatalog) -> TestCatalog:
    return TestCatalog(
        version=row.version,
        mappings=_catalog_from_dict(row.mappings),
        digest=row.digest,
    )


def _from_catalog(catalog: TestCatalog) -> CoreTestCatalog:
    return CoreTestCatalog(
        version=catalog.version,
        mappings=_catalog_to_dict(catalog),
        digest=catalog.digest,
    )


def _to_matrix(row: CoreCoverageMatrix) -> CoverageMatrix:
    mappings = {
        key: tuple(values) for key, values in row.mappings.items()
    }
    return CoverageMatrix(
        version=row.version,
        framework=row.framework,
        mappings=mappings,
        total_items=row.total_items,
        digest=row.digest,
    )


def _from_matrix(matrix: CoverageMatrix) -> CoreCoverageMatrix:
    return CoreCoverageMatrix(
        version=matrix.version,
        framework=matrix.framework,
        mappings={key: list(values) for key, values in matrix.mappings.items()},
        total_items=matrix.total_items,
        digest=matrix.digest,
    )


class SqlAlchemyCatalogRepository:
    """Persisted TestCatalog + CoverageMatrix store."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add_catalog(self, catalog: TestCatalog) -> None:
        self._session.merge(_from_catalog(catalog))

    def get_catalog_by_version(self, version: str) -> TestCatalog | None:
        row = self._session.get(CoreTestCatalog, version)
        return _to_catalog(row) if row else None

    def latest_catalog(self) -> TestCatalog | None:
        """Return the highest-versioned catalog, or None if the store is empty."""
        row = self._session.execute(
            select(CoreTestCatalog).order_by(CoreTestCatalog.version.desc()).limit(1)
        ).scalars().first()
        return _to_catalog(row) if row else None

    def add_coverage(self, matrix: CoverageMatrix) -> None:
        self._session.merge(_from_matrix(matrix))

    def get_coverage(self, version: str, framework: str) -> CoverageMatrix | None:
        stmt = select(CoreCoverageMatrix).where(
            CoreCoverageMatrix.version == version,
            CoreCoverageMatrix.framework == framework,
        )
        row = self._session.execute(stmt).scalars().first()
        return _to_matrix(row) if row else None


__all__ = [
    "SqlAlchemyCatalogRepository",
    "_to_catalog",
    "_from_catalog",
    "_to_matrix",
    "_from_matrix",
]
