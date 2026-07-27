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


# --- Findings ---
class FindingCreate(BaseModel):
    title: str
    asset: str
    severity: str = "medium"
    cwe: list[str] = []


class FindingOut(BaseModel):
    id: str
    fingerprint: str
    title: str
    asset: str
    severity: str
    cwe: list[str]
    cve: list[str]
    owasp: list[str]
    status: str


# --- Intel (vulnerability knowledge layer) ---
class AffectedProductOut(BaseModel):
    vendor: str
    product: str
    cpe: str | None
    package: str | None
    version_range: str
    fixed_versions: list[str]


class ExploitationSignalOut(BaseModel):
    kev: bool
    epss_score: float
    public_exploit: bool
    ransomware: bool
    active_exploitation: bool


class VulnerabilityOut(BaseModel):
    canonical_id: str
    aliases: list[str]
    description: str
    # source name -> CVSS score; the multi-source map is preserved (no "winner").
    cvss: dict[str, float]
    cwe: list[str]
    references: list[str]
    published_at: datetime
    affected_products: list[AffectedProductOut]
    exploitation_signal: ExploitationSignalOut
    digest: str


# --- Updates (knowledge bundle) ---
class UpdateBundleOut(BaseModel):
    bundle_id: str
    version: str
    digest: str
    staged_at: datetime | None = None


class ActiveBundleOut(BaseModel):
    active_bundle_id: str | None
    bundle: UpdateBundleOut | None


# --- Audit (tamper-evident hash chain) ---
class AuditEventOut(BaseModel):
    id: str
    actor: str
    action: str
    resource_type: str
    resource_id: str
    payload: dict[str, object]
    previous_hash: str
    event_hash: str
    occurred_at: datetime


class AuditVerifyOut(BaseModel):
    valid: bool
    event_count: int
