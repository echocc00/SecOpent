# src/secopent/interfaces/api/routers/__init__.py
"""REST API routers, one module per resource (Phase A P1, W1)."""
from __future__ import annotations

from .assessments import router as assessments_router
from .projects import router as projects_router
from .scopes import router as scopes_router
from .tools import router as tools_router

__all__ = ["projects_router", "scopes_router", "assessments_router", "tools_router"]
