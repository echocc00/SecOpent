# src/secopent/infrastructure/db/evidence_models.py
"""ORM table for content-addressed evidence (§13, three-layer)."""
from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from .core_models import CoreBase


class CoreEvidence(CoreBase):
    """One content-addressed evidence object in a single layer.

    ``sha256`` is the content digest (``sha256:<hex>``); ``storage_uri`` is the
    CAS location. For REDACTED/SUMMARY layers ``source_id`` links back to the
    RAW evidence it was derived from; ``signature`` is an independent signature
    over the derived content (empty for RAW).
    """

    __tablename__ = "core_evidence"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    layer: Mapped[str] = mapped_column(String(16), nullable=False)
    sha256: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    storage_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    source_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    signature: Mapped[str] = mapped_column(String(256), nullable=False, default="")
