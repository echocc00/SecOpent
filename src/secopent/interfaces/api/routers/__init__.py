# src/secopent/interfaces/api/routers/__init__.py
"""REST API routers, one module per resource (Phase A P1, W1)."""
from __future__ import annotations

from .appmodels import router as appmodels_router
from .approvals import router as approvals_router
from .assessments import router as assessments_router
from .assets import router as assets_router
from .audit import router as audit_router
from .cases import router as cases_router
from .evidence import router as evidence_router
from .findings import router as findings_router
from .intel import router as intel_router
from .jobs import router as jobs_router
from .plans import router as plans_router
from .projects import router as projects_router
from .reports import router as reports_router
from .scopes import router as scopes_router
from .signing_keys import router as signing_keys_router
from .tools import router as tools_router
from .updates import router as updates_router

__all__ = [
    "projects_router",
    "scopes_router",
    "assessments_router",
    "tools_router",
    "findings_router",
    "intel_router",
    "updates_router",
    "audit_router",
    "plans_router",
    "approvals_router",
    "jobs_router",
    "assets_router",
    "evidence_router",
    "reports_router",
    "cases_router",
    "appmodels_router",
    "signing_keys_router",
]
