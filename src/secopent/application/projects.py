from __future__ import annotations
import uuid
from ..domain.projects.models import Project
from .ports.repositories import ProjectRepository


class ProjectService:
    def __init__(self, repo: ProjectRepository) -> None:
        self._repo = repo

    def create(self, *, name: str) -> Project:
        project = Project.create(project_id=f"proj-{uuid.uuid4().hex[:12]}", name=name)
        self._repo.add(project)
        return project
