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
    requests_per_second: float = 5.0
    concurrency: int = 3
    max_requests: int = 50_000


class ScopeLimitsOut(BaseModel):
    requests_per_second: float
    concurrency: int
    max_requests: int


class ScopeSnapshotOut(BaseModel):
    id: str
    project_id: str
    include: list[str]
    exclude: list[str]
    ports: list[int]
    cloud_accounts: list[str]
    limits: ScopeLimitsOut
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
    active_plan_id: str | None = None
    approval_id: str | None = None


# --- Findings ---
class FindingCreate(BaseModel):
    title: str
    asset: str
    severity: str = "medium"
    cwe: list[str] = []
    assessment_id: str = ""


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
    assessment_id: str
    oracle_verdict: str


class FindingVerdict(BaseModel):
    # Oracle N/N reproduction verdict: pending/confirmed/refuted/inconclusive.
    verdict: str
    # Written by the deterministic oracle or a human manual override; an agent
    # may never set it (LLM boundary).
    actor_role: str = "human"


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


class SyncBundleBody(BaseModel):
    # Registry source, e.g. "github:secopent/bundles:v2026.07".
    source: str
    # "human" or "agent"; syncing bundles is human-only (LLM boundary).
    actor_role: str = "human"
    # Signing key whose public key verifies the bundle (default: server default).
    key_id: str | None = None


class SyncResultOut(BaseModel):
    bundle_id: str
    version: str
    digest: str
    previous_bundle_id: str | None


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


# --- Drift (AppModel re-import diff) ---
class DriftRequest(BaseModel):
    states: list[str]
    transitions: list[TransitionIn]


class DriftReportOut(BaseModel):
    app_id: str
    added: list[str]
    removed: list[str]
    changed: list[str]
    has_drift: bool


# --- Emergency stop ---
class StopRequest(BaseModel):
    actor: str
    reason: str
    actor_role: str = "human"


class StartRequest(BaseModel):
    """Trigger assessment execution (POST /assessments/{id}/start, v0.1.2 P0)."""
    actor_role: str = "human"


class EmergencyReportOut(BaseModel):
    triggered: bool
    revoked_permits: int
    terminated_containers: int
    evidence_preserved: bool
    actor: str
    reason: str


# --- Knowledge health ---
class HealthAlertOut(BaseModel):
    kind: str
    source: str
    details: dict[str, object]


class HealthReportOut(BaseModel):
    alerts: list[HealthAlertOut]


# --- Report generation ---
class ReportGenerate(BaseModel):
    assessment_id: str
    title: str = "Security Assessment Report"
    # With polish, the LLM polishes the executive summary narrative (numbers
    # stay from the deterministic layer; added as an extra section, LLM boundary).
    polish: bool = False


# --- Plans ---
class PlanStepIn(BaseModel):
    key: str
    runner: str
    risk: str
    parameters: dict[str, object] = {}
    dependencies: list[str] = []


class PlanStepOut(BaseModel):
    key: str
    runner: str
    risk: str
    parameters: dict[str, object]
    dependencies: list[str]


class PlanCreate(BaseModel):
    assessment_id: str
    steps: list[PlanStepIn]


class PlanOut(BaseModel):
    id: str
    assessment_id: str
    version: int
    digest: str
    steps: list[PlanStepOut]


# --- Approvals ---
class ApprovalCreate(BaseModel):
    assessment_id: str
    approved_by: str
    approved_risks: list[str] = []
    approved_capabilities: list[str] = []
    # Approval is a human-only decision (LLM boundary); agents are rejected.
    actor_role: str = "human"


class ApprovalOut(BaseModel):
    id: str
    assessment_id: str
    plan_digest: str
    scope_digest: str
    mode: str
    approved_risks: list[str]
    approved_capabilities: list[str]
    approved_by: str
    digest: str


class ApprovalRequestOut(BaseModel):
    """A pending approval: an assessment awaiting a human decision."""

    assessment_id: str
    project_id: str
    mode: str
    plan_id: str | None
    plan_digest: str | None
    scope_digest: str | None


class ApprovalDecisionOut(BaseModel):
    """A decided approval (approved or rejected)."""

    assessment_id: str
    project_id: str
    decision: str  # "approved" | "rejected"
    decided_by: str
    reason: str = ""
    approved_risks: list[str] = []
    approved_capabilities: list[str] = []
    plan_digest: str = ""
    scope_digest: str = ""


class ApprovalReject(BaseModel):
    assessment_id: str
    rejected_by: str
    reason: str
    # Rejection is a human-only decision (LLM boundary); agents are rejected.
    actor_role: str = "human"


# --- Jobs ---
class JobOut(BaseModel):
    id: str
    plan_step_key: str
    idempotency_key: str
    status: str
    attempt: int
    max_attempts: int
    lease_owner: str | None
    result_digest: str
    failure_class: str
    dependencies: list[str]


# --- Assets (discovery graph) ---
class AssetNodeOut(BaseModel):
    type: str
    value: str


class AssetEdgeOut(BaseModel):
    src: AssetNodeOut
    dst: AssetNodeOut
    rel: str


class AssetGraphOut(BaseModel):
    nodes: list[AssetNodeOut]
    edges: list[AssetEdgeOut]


# --- Evidence (three-layer, content-addressed) ---
class EvidenceOut(BaseModel):
    id: str
    layer: str
    sha256: str
    storage_uri: str
    source_id: str
    signature: str


# --- Reports ---
class ReportSectionOut(BaseModel):
    name: str
    content: str


class ReportOut(BaseModel):
    id: str
    assessment_id: str
    title: str
    sections: list[ReportSectionOut]
    finding_count: int
    coverage_rate: float
    completeness_ok: bool
    status: str
    digest: str


# --- Cases (CaseStudio lifecycle) ---
class CaseStepIn(BaseModel):
    id: str
    action: str
    spec: dict[str, object] = {}


class CaseCreate(BaseModel):
    id: str
    version: str
    author: str
    risk: str
    target_type: str
    # Named ``case_schema`` (not ``schema``) to avoid shadowing
    # ``BaseModel.schema``; maps to the domain CaseDefinition.schema field.
    case_schema: str
    steps: list[CaseStepIn]
    cwe: list[str] = []
    cve: list[str] = []
    owasp: list[str] = []
    origin: str = "manual"
    yaml: str = ""


class CaseStepOut(BaseModel):
    id: str
    action: str
    spec: dict[str, object]


class CaseOut(BaseModel):
    id: str
    version: str
    author: str
    risk: str
    target_type: str
    case_schema: str
    status: str
    origin: str
    signature: str
    steps: list[CaseStepOut]
    cwe: list[str]
    cve: list[str]
    owasp: list[str]
    yaml: str


class CaseAnalysisOut(BaseModel):
    """Read-only risk/schema analysis for the CaseStudio YAML editor (decision D).

    Computed by the deterministic RiskAnalyzer (never the LLM): ``computed_risk``
    is None when a deny-listed pattern is present; ``risk_ok`` is True when the
    declared risk is >= the computed risk. ``llm_risk`` is an optional LLM DRAFT
    suggestion (§3.3 dual channel) - advisory only, NEVER overrides the computed
    risk (LLM boundary).
    """

    case_id: str
    declared_risk: str
    computed_risk: str | None
    denied: bool
    risk_ok: bool
    schema_ok: bool
    errors: list[str]
    llm_risk: str | None = None


class CaseAction(BaseModel):
    # "human" or "agent"; review/sign/publish are human-only (LLM boundary).
    actor_role: str = "human"
    # Signing key to use for sign actions (defaults to the server's default key).
    key_id: str | None = None


class CaseYamlUpdate(BaseModel):
    yaml: str


# --- Signing keys (server-held Ed25519) ---
class SigningKeyOut(BaseModel):
    key_id: str
    name: str
    public_key: str
    created_at: datetime
    archived: bool = False


class CreateSigningKey(BaseModel):
    name: str
    # Creating a signing key is a privileged admin action (LLM boundary);
    # listing keys (GET) stays open for the UI key selector.
    actor_role: str = "human"


# --- Catalog (knowledge layer: required test classes per asset type) ---
class RequiredTestClassIn(BaseModel):
    id: str
    cwe: list[str] = []
    owasp: list[str] = []
    risk: str


class CatalogCreate(BaseModel):
    version: str
    mappings: dict[str, list[RequiredTestClassIn]]


class CatalogOut(BaseModel):
    version: str
    digest: str
    mappings: dict[str, list[RequiredTestClassIn]]


# Generic actor-role body shared by human-only lifecycle actions (cases/appmodels).
ActorRoleBody = CaseAction


# --- AppModels (CaseStudio model-driven logic) ---
class TransitionIn(BaseModel):
    id: str
    from_state: str
    to_state: str
    endpoint: str
    params: list[str] = []
    idempotent: bool = False


class InvariantIn(BaseModel):
    id: str
    expr: str


class FieldIn(BaseModel):
    name: str
    type: str
    range: list[object] | None = None
    trusted_source: str = "client"


class RoleIn(BaseModel):
    id: str
    capabilities: list[str] = []


class AppModelCreate(BaseModel):
    app_id: str
    version: str
    states: list[str]
    transitions: list[TransitionIn] = []
    invariants: list[InvariantIn] = []
    fields: list[FieldIn] = []
    roles: list[RoleIn] = []
    out_of_scope_rules: list[str] = []
    # True when an LLM proposed the model (starts at LLM_PROPOSED, needs human
    # validation); False for a manually-authored draft (starts at DRAFT).
    llm_proposed: bool = False


class AppModelRevise(AppModelCreate):
    # Target version for the new draft; auto-bumped from the source if omitted.
    new_version: str | None = None


class AppModelImport(BaseModel):
    # Import an AppModel from an OpenAPI/Postman/traffic spec. With use_llm the
    # LLM PROPOSES business states/invariants (model lands as LLM_PROPOSED for
    # human validation); without it the deterministic importer draft is DRAFT.
    source_type: str
    spec: dict[str, object]
    use_llm: bool = False


class TransitionOut(BaseModel):
    id: str
    from_state: str
    to_state: str
    endpoint: str
    params: list[str]
    idempotent: bool


class InvariantOut(BaseModel):
    id: str
    expr: str


class FieldOut(BaseModel):
    name: str
    type: str
    range: list[object] | None
    trusted_source: str


class RoleOut(BaseModel):
    id: str
    capabilities: list[str]


class AppModelOut(BaseModel):
    app_id: str
    version: str
    states: list[str]
    transitions: list[TransitionOut]
    invariants: list[InvariantOut]
    fields: list[FieldOut]
    roles: list[RoleOut]
    out_of_scope_rules: list[str]
    status: str
    digest: str
    signature: str | None
