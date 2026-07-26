# src/secopent/interfaces/api/schemas.py
"""Pydantic request/response schemas for the REST API (Phase A P1, W1).

Each resource has a ``XxxCreate`` (command payload) and ``XxxOut`` (query
representation). These are translated to/from the framework-free domain
dataclasses at the router boundary so the domain stays free of Pydantic.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


# --- Projects ---
class ProjectCreate(BaseModel):
    name: str


class ProjectOut(BaseModel):
    id: str
    name: str
    status: str
    created_at: datetime


# --- Scopes ---
class ScopeDraftCreate(BaseModel):
    project_id: str
    include: list[str]
    exclude: list[str] = []
    ports: list[int] = [80, 443]
    approved_by: str = "analyst"


class ScopeSnapshotOut(BaseModel):
    id: str
    project_id: str
    include: list[str]
    exclude: list[str]
    ports: list[int]
    cloud_accounts: list[str]
    approved_by: str
    digest: str


# --- Assessments ---
class AssessmentCreate(BaseModel):
    project_id: str
    scope_snapshot_id: str
    mode: str = "approval"


class AssessmentOut(BaseModel):
    id: str
    project_id: str
    scope_snapshot_id: str
    mode: str
    status: str
