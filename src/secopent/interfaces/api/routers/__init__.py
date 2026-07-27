# src/secopent/interfaces/api/routers/__init__.py
"""REST API routers, one module per resource (Phase A P1, W1)."""
from __future__ import annotations

from .assessments import router as assessments_router
from .audit import router as audit_router
from .findings import router as findings_router
from .intel import router as intel_router
from .projects import router as projects_router
from .scopes import router as scopes_router
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
]
