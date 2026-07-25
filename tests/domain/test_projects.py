from __future__ import annotations

import pytest

from secopent.domain.common.errors import DomainValidationError
from secopent.domain.projects.models import Project, ProjectStatus


def test_project_create_normalizes_name() -> None:
    project = Project.create(project_id="project-1", name="  Lab Assessment  ")
    assert project.name == "Lab Assessment"
    assert project.status is ProjectStatus.ACTIVE
    assert project.created_at.tzinfo is not None


def test_project_rejects_empty_name() -> None:
    with pytest.raises(DomainValidationError, match="name"):
        Project.create(project_id="project-1", name="   ")


def test_project_rejects_empty_id() -> None:
    with pytest.raises(DomainValidationError, match="id"):
        Project.create(project_id="  ", name="Lab")


def test_project_status_values() -> None:
    assert ProjectStatus.ACTIVE.value == "active"
    assert ProjectStatus.ARCHIVED.value == "archived"
