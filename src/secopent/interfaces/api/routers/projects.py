# src/secopent/interfaces/api/routers/projects.py
"""Projects resource router (Phase A P1, W1)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ....application.projects import ProjectService
from ....infrastructure.repositories.sqlalchemy_core import SqlAlchemyProjectRepository
from ..deps import DbSession
from ..schemas import ProjectCreate, ProjectOut

router = APIRouter(prefix="/projects", tags=["projects"])


def _to_out(project) -> ProjectOut:  # type: ignore[no-untyped-def]
    return ProjectOut(
        id=project.id,
        name=project.name,
        status=project.status.value,
        created_at=project.created_at,
    )


@router.post("", status_code=201, response_model=ProjectOut)
def create_project(payload: ProjectCreate, session: DbSession) -> ProjectOut:
    service = ProjectService(SqlAlchemyProjectRepository(session))
    project = service.create(name=payload.name)
    return _to_out(project)


@router.get("", response_model=list[ProjectOut])
def list_projects(session: DbSession) -> list[ProjectOut]:
    repo = SqlAlchemyProjectRepository(session)
    return [_to_out(p) for p in repo.list()]


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project_id: str, session: DbSession) -> ProjectOut:
    project = SqlAlchemyProjectRepository(session).get(project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="project not found")
    return _to_out(project)
