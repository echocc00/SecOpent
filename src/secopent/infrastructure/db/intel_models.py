# src/secopent/infrastructure/db/intel_models.py
"""SQLAlchemy ORM models for the intel knowledge layer.

Persisted entities (one table each):

* ``CoreVulnerability`` - canonical CVE/OSV record with multi-source CVSS
* ``CoreAffectedProduct`` - one (vendor, product, version_range) per vuln
* ``CoreExploitationSignal`` - KEV/EPSS/public-exploit/ransomware/active
* ``CoreDetectionMapping`` - how a vuln surfaces through a detection case
* ``CoreIntelSnapshot`` - point-in-time snapshot of the intel store (per source)

The ``core_vulnerabilities_fts`` FTS5 virtual table is created via raw SQL in
the test/production bootstrap (SQLAlchemy 2.0 does not model FTS5 virtual
tables declaratively). The repository keeps the FTS row in sync with
``CoreVulnerability`` on every insert.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from .core_models import CoreBase


class CoreVulnerability(CoreBase):
    """Canonical vulnerability record.

    ``cvss`` is stored as JSON of ``{source: {"score": float, "provenance":
    {source, fetched_at, source_version}}}`` because the multi-source map
    cannot fit a flat column. ``aliases`` and ``cwe`` are JSON arrays.
    ``references`` is a JSON array of URL strings.
    """

    __tablename__ = "core_vulnerabilities"

    canonical_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    aliases: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False)
    cvss: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    cwe: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    references: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    digest: Mapped[str] = mapped_column(String(80), nullable=False, index=True)


class CoreAffectedProduct(CoreBase):
    """One affected product record linked to a vulnerability."""

    __tablename__ = "core_affected_products"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[str] = mapped_column(
        ForeignKey("core_vulnerabilities.canonical_id"), nullable=False, index=True
    )
    vendor: Mapped[str] = mapped_column(String(256), nullable=False)
    product: Mapped[str] = mapped_column(String(256), nullable=False)
    cpe: Mapped[str | None] = mapped_column(String(256), nullable=True)
    package: Mapped[str | None] = mapped_column(String(256), nullable=True)
    version_range: Mapped[str] = mapped_column(String(256), nullable=False)
    fixed_versions: Mapped[list[Any]] = mapped_column(JSON, nullable=False)


class CoreExploitationSignal(CoreBase):
    """Wild-exploitation signals for one vulnerability (1:1)."""

    __tablename__ = "core_exploitation_signals"

    vulnerability_id: Mapped[str] = mapped_column(
        ForeignKey("core_vulnerabilities.canonical_id"), primary_key=True
    )
    kev: Mapped[bool] = mapped_column(nullable=False)
    epss_score: Mapped[float] = mapped_column(Float, nullable=False)
    public_exploit: Mapped[bool] = mapped_column(nullable=False)
    ransomware: Mapped[bool] = mapped_column(nullable=False)
    active_exploitation: Mapped[bool] = mapped_column(nullable=False)


class CoreDetectionMapping(CoreBase):
    """How a vulnerability surfaces through one detection case."""

    __tablename__ = "core_detection_mappings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[str] = mapped_column(
        ForeignKey("core_vulnerabilities.canonical_id"), nullable=False, index=True
    )
    case_version: Mapped[str] = mapped_column(String(64), nullable=False)
    detection_type: Mapped[str] = mapped_column(String(64), nullable=False)
    risk: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)


class CoreIntelSnapshot(CoreBase):
    """Point-in-time snapshot of the intel store per source.

    ``source`` is e.g. ``"osv"``, ``"kev"``, ``"epss"``. ``cursor`` is the
    source-specific incremental-fetch cursor (e.g. OSV ``last_modified``
    timestamp). ``counts`` records row counts per entity type for health
    monitoring (Task 7).
    """

    __tablename__ = "core_intel_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source_version: Mapped[str] = mapped_column(String(64), nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    cursor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    counts: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
