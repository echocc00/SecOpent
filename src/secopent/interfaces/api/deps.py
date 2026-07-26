# src/secopent/interfaces/api/deps.py
"""FastAPI dependencies for the REST API (Phase A P1, W1).

``get_db`` yields a request-scoped session from the ``Database`` stored on
``app.state`` (set in ``create_app``). Routers depend on it via ``Depends(get_db)``.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session


def get_db(request: Request) -> Iterator[Session]:
    """Yield a request-scoped session from the app's Database."""
    db = request.app.state.db
    yield from db.session()


# Reusable FastAPI dependency annotation (avoids B008 on Depends defaults).
DbSession = Annotated[Session, Depends(get_db)]
