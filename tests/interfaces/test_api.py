"""TDD tests for the FastAPI surface (M4 Task 7, §13 command/query + idempotency)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from secopent.interfaces.api.main import create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_create_and_get_finding(client: TestClient) -> None:
    created = client.post(
        "/findings",
        json={
            "title": "SQLi",
            "asset": "https://x.test/login",
            "severity": "high",
            "cwe": ["CWE-89"],
        },
    )
    assert created.status_code == 201
    finding = created.json()
    # DB-backed findings use a deterministic content-addressed id.
    assert finding["id"].startswith("finding:")
    assert finding["severity"] == "high"

    fetched = client.get(f"/findings/{finding['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["title"] == "SQLi"


def test_list_findings(client: TestClient) -> None:
    client.post("/findings", json={"title": "a", "asset": "https://x.test/"})
    client.post("/findings", json={"title": "b", "asset": "https://x.test/"})
    listed = client.get("/findings")
    assert listed.status_code == 200
    assert len(listed.json()) == 2


def test_unknown_finding_404(client: TestClient) -> None:
    assert client.get("/findings/nope").status_code == 404


def test_invalid_payload_422(client: TestClient) -> None:
    # Missing required 'asset'.
    assert client.post("/findings", json={"title": "x"}).status_code == 422


def test_idempotency_key_prevents_duplicate(client: TestClient) -> None:
    payload = {"title": "SQLi", "asset": "https://x.test/login"}
    first = client.post("/findings", json=payload, headers={"Idempotency-Key": "key-1"})
    second = client.post("/findings", json=payload, headers={"Idempotency-Key": "key-1"})
    assert first.json()["id"] == second.json()["id"]  # same resource, not duplicated
    assert len(client.get("/findings").json()) == 1


def test_sse_streams_events(client: TestClient) -> None:
    with client.stream("GET", "/assessments/assess-1/events") as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join(chunk for chunk in response.iter_text())
    assert "queued" in body
    assert "completed" in body
    assert "assess-1" in body
