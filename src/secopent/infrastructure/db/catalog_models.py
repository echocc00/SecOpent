# src/secopent/infrastructure/db/catalog_models.py
"""SQLAlchemy ORM models for the TestCatalog / CoverageMatrix knowledge layer.

The catalog is the curated "what to test" mapping (asset type -> required test
classes) and the coverage matrix maps a framework (OWASP WSTG) to test class
ids. Both are versioned, content-addressed by ``digest``, and pinned per
Assessment so coverage decisions remain reproducible across catalog updates.

The ORM classes inherit from the same ``CoreBase`` declared in
``core_models.py`` so a single ``CoreBase.metadata.create_all(engine)`` call
creates every M0+M1 table.
"""
from __future__ import annotations

from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from .core_models import CoreBase


class CoreTestCatalog(CoreBase):
    """Persisted TestCatalog row.

    ``mappings`` stores the asset-type -> required-test-classes dict as JSON
    (the dict is keyed by ``AssetType`` enum value; values are tuples of
    ``RequiredTestClass`` dataclass dicts). The ``digest`` column is the
    canonical SHA-256 over the catalog content.
    """

    __tablename__ = "core_test_catalogs"

    version: Mapped[str] = mapped_column(String(64), primary_key=True)
    mappings: Mapped[dict] = mapped_column(JSON, nullable=False)
    digest: Mapped[str] = mapped_column(String(80), nullable=False, index=True)


class CoreCoverageMatrix(CoreBase):
    """Persisted CoverageMatrix row.

    The (version, framework) pair uniquely identifies a matrix; ``mappings``
    is the framework-item-id -> test-class-ids dict stored as JSON.
    """

    __tablename__ = "core_coverage_matrices"

    version: Mapped[str] = mapped_column(String(64), primary_key=True)
    framework: Mapped[str] = mapped_column(String(64), primary_key=True)
    mappings: Mapped[dict] = mapped_column(JSON, nullable=False)
    total_items: Mapped[int] = mapped_column(nullable=False)
    digest: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
