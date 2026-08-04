"""Project archive/reactivate transitions (W3-D T3)."""
from __future__ import annotations

import pytest

from secopent.domain.common.errors import DomainValidationError
from secopent.domain.projects.models import Project, ProjectStatus


def test_active_can_archive() -> None:
    p = Project.create(project_id="p1", name="Acme")
    archived = p.archive()
    assert archived.status is ProjectStatus.ARCHIVED


def test_archived_can_reactivate() -> None:
    p = Project.create(project_id="p1", name="Acme").archive()
    active = p.reactivate()
    assert active.status is ProjectStatus.ACTIVE


def test_archive_idempotent_on_archived() -> None:
    """Archiving an already-archived project is a no-op (not an error)."""
    p = Project.create(project_id="p1", name="Acme").archive()
    assert p.archive().status is ProjectStatus.ARCHIVED


def test_reactivate_rejects_already_active() -> None:
    p = Project.create(project_id="p1", name="Acme")  # ACTIVE
    with pytest.raises(DomainValidationError):
        p.reactivate()


def test_transitions_preserve_id_name_created_at() -> None:
    p = Project.create(project_id="p1", name="Acme")
    archived = p.archive()
    assert archived.id == p.id
    assert archived.name == p.name
    assert archived.created_at == p.created_at
