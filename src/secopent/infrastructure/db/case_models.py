# src/secopent/infrastructure/db/case_models.py
"""ORM table for versioned, signed case definitions (§11.5)."""
from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .core_models import CoreBase


class CoreCase(CoreBase):
    """A persisted CaseDefinition.

    Scalar lifecycle/attribution fields are columns; the nested DSL parts
    (steps, assertions) and the list fields (preconditions, evidence_req,
    cwe/cve/owasp) are JSON. ``verification`` is a nullable JSON object
    (``{method, reproduce}``). ``schema`` is the case-schema identifier.
    """

    __tablename__ = "core_cases"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    author: Mapped[str] = mapped_column(String(128), nullable=False)
    risk: Mapped[str] = mapped_column(String(16), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    schema: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    origin: Mapped[str] = mapped_column(String(24), nullable=False)
    signature: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    min_engine_version: Mapped[str] = mapped_column(String(16), nullable=False)
    steps: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    preconditions: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    assertions: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    evidence_req: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    cwe: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    cve: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    owasp: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    verification: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    yaml: Mapped[str] = mapped_column(Text, nullable=False, default="")
