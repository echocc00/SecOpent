# src/secopent/infrastructure/db/asset_models.py
"""ORM tables for the asset graph (relation table, §6)."""
from __future__ import annotations

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from .core_models import CoreBase


class CoreAssetNode(CoreBase):
    __tablename__ = "core_asset_nodes"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    asset_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(512), nullable=False)


class CoreAssetEdge(CoreBase):
    __tablename__ = "core_asset_edges"
    id: Mapped[str] = mapped_column(String(256), primary_key=True)
    src_id: Mapped[str] = mapped_column(
        ForeignKey("core_asset_nodes.id"), nullable=False, index=True
    )
    dst_id: Mapped[str] = mapped_column(
        ForeignKey("core_asset_nodes.id"), nullable=False
    )
    rel: Mapped[str] = mapped_column(String(32), nullable=False)
