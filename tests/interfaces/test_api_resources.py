"""Tests for the W1 resource API routers (projects/scopes/assessments).

These run against a real temporary SQLite database via the FastAPI TestClient,
exercising the DB-backed routers end-to-end (create -> persist -> read).
"""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.interfaces.api.main import create_app


@pytest.fixture
def client(tmp_path) -> Iterator[TestClient]:  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "api.db")
    app = create_app(engine)
    with TestClient(app) as test_client:
        yield test_client


def test_openapi_spec_accessible(client: TestClient) -> None:
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    paths = resp.json()["paths"]
    assert "/projects" in paths
    assert "/scopes/draft" in paths
    assert "/assessments" in paths
    assert "/tools" in paths


def test_tools_lists_adapters(client: TestClient) -> None:
    resp = client.get("/tools")
    assert resp.status_code == 200
    tools = resp.json()
    keys = {t["key"] for t in tools}
    assert "nuclei" in keys
    assert "nmap" in keys
    assert "prowler" in keys
    nuclei = next(t for t in tools if t["key"] == "nuclei")
    assert nuclei["domain"] == "web"
    assert nuclei["digest"].startswith("sha256:")


def test_project_create_get_list(client: TestClient) -> None:
    created = client.post("/projects", json={"name": "Acme"})
    assert created.status_code == 201
    project = created.json()
    assert project["name"] == "Acme"
    assert project["status"] == "active"
    project_id = project["id"]

    fetched = client.get(f"/projects/{project_id}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == project_id

    listed = client.get("/projects")
    assert listed.status_code == 200
    assert any(p["id"] == project_id for p in listed.json())


def test_project_not_found(client: TestClient) -> None:
    assert client.get("/projects/nope").status_code == 404


def test_scope_freeze_and_get(client: TestClient) -> None:
    project = client.post("/projects", json={"name": "Acme"}).json()
    created = client.post(
        "/scopes/draft",
        json={"project_id": project["id"], "include": ["https://acme.test"]},
    )
    assert created.status_code == 201
    snapshot = created.json()
    assert snapshot["project_id"] == project["id"]
    # Scope normalization appends a trailing slash to a bare domain URL.
    assert "https://acme.test/" in snapshot["include"]
    assert snapshot["digest"].startswith("sha256:")

    fetched = client.get(f"/scopes/{snapshot['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == snapshot["id"]


def test_assessment_create_and_get(client: TestClient) -> None:
    project = client.post("/projects", json={"name": "Acme"}).json()
    scope = client.post(
        "/scopes/draft",
        json={"project_id": project["id"], "include": ["https://acme.test"]},
    ).json()
    created = client.post(
        "/assessments",
        json={"project_id": project["id"], "scope_snapshot_id": scope["id"]},
    )
    assert created.status_code == 201
    assessment = created.json()
    assert assessment["project_id"] == project["id"]
    assert assessment["scope_snapshot_id"] == scope["id"]
    assert assessment["status"] == "draft"

    fetched = client.get(f"/assessments/{assessment['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == assessment["id"]


def test_assessment_invalid_mode_422(client: TestClient) -> None:
    project = client.post("/projects", json={"name": "Acme"}).json()
    scope = client.post(
        "/scopes/draft",
        json={"project_id": project["id"], "include": ["https://acme.test"]},
    ).json()
    resp = client.post(
        "/assessments",
        json={
            "project_id": project["id"],
            "scope_snapshot_id": scope["id"],
            "mode": "bogus",
        },
    )
    assert resp.status_code == 422
