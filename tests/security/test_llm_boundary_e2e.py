"""LLM boundary e2e tests (§3.3): the LLM proposes/drafts ONLY, never decides.

These verify, through the REST API with a mock LLM backend, that:
1. An LLM-proposed AppModel import lands as LLM_PROPOSED (never SIGNED).
2. An LLM-drafted case risk is advisory only - the computed risk decides.
3. Report polishing adds a narrative section; the deterministic numbers
   (finding_count) are untouched.

A mock backend records every prompt so we also prove the LLM was actually
called. A MiniMax smoke test (skipped without MINIMAX_API_KEY) exercises the
real remote path once.
"""
from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from secopent.application.remote_model import RemoteModelGateway
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.evidence_store.redaction import RedactionEngine
from secopent.interfaces.api.main import create_app


class MockLLMBackend:
    """A ModelBackend that returns a canned response and records prompts."""

    def __init__(self, response: str) -> None:
        self.response = response
        self.calls: list[str] = []

    def complete(self, prompt: str) -> str:
        self.calls.append(prompt)
        return self.response


@pytest.fixture
def mock_llm_app(tmp_path) -> Iterator[tuple[TestClient, MockLLMBackend]]:  # type: ignore[no-untyped-def]
    backend = MockLLMBackend("")
    app = create_app(create_sqlite_engine(tmp_path / "llm.db"))
    app.state.model_gateway = RemoteModelGateway(
        local_backend=backend, redactor=RedactionEngine()
    )
    with TestClient(app) as client:
        yield client, backend


_OPENAPI_SPEC = {
    "info": {"title": "shop", "version": "1.0"},
    "paths": {
        "/cart": {
            "post": {
                "operationId": "addToCart",
                "parameters": [{"name": "item_id", "schema": {"type": "integer"}}],
            }
        },
        "/checkout": {"post": {"operationId": "checkout", "parameters": []}},
    },
}


def test_llm_proposed_model_is_never_signed(mock_llm_app) -> None:  # type: ignore[no-untyped-def]
    client, backend = mock_llm_app
    backend.response = (
        '{"states": ["checkout_state"], '
        '"invariants": [{"id": "inv-total", "expr": "cart.total >= 0"}]}'
    )
    resp = client.post(
        "/appmodels/import",
        json={"source_type": "openapi", "spec": _OPENAPI_SPEC, "use_llm": True},
    )
    assert resp.status_code == 201
    model = resp.json()
    # The LLM proposed enrichment, but the model is NOT signed (human-only).
    assert model["status"] == "llm_proposed"
    assert "checkout_state" in model["states"]
    assert any(i["id"] == "inv-total" for i in model["invariants"])
    assert backend.calls  # the LLM was actually called


def test_llm_risk_is_advisory_only(mock_llm_app) -> None:  # type: ignore[no-untyped-def]
    client, backend = mock_llm_app
    case = client.post(
        "/cases",
        json={
            "id": "case-1",
            "version": "1.0",
            "author": "e2e",
            "risk": "low",
            "target_type": "web_app",
            "case_schema": "secopent-case/v1",
            "steps": [{"id": "s1", "action": "http.request", "spec": {"method": "GET"}}],
        },
    ).json()
    # The LLM suggests a wild risk; the deterministic analyzer must still decide.
    backend.response = "destructive"
    analysis = client.post(
        f"/cases/{case['id']}/analyze", params={"use_llm": "true"}
    ).json()
    assert analysis["computed_risk"] == "low"  # deterministic, authoritative
    assert analysis["llm_risk"] == "destructive"  # advisory only
    assert analysis["llm_risk"] != analysis["computed_risk"]  # not overridden
    assert backend.calls


def test_report_polish_preserves_deterministic_numbers(mock_llm_app) -> None:  # type: ignore[no-untyped-def]
    client, backend = mock_llm_app
    assessment = _seed_assessment(client)
    client.post(
        "/findings",
        json={"title": "SQLi", "asset": "https://x.test/", "severity": "high",
              "assessment_id": assessment["id"]},
    )
    backend.response = "Polished: the assessment found issues that need remediation."
    report = client.post(
        "/reports",
        json={"assessment_id": assessment["id"], "title": "Report", "polish": True},
    ).json()
    sections = {s["name"] for s in report["sections"]}
    # Deterministic section preserved AND a polished section added.
    assert "executive_summary" in sections
    assert "executive_summary_polished" in sections
    # The finding count is deterministic (from data), not from the LLM.
    assert report["finding_count"] == 1
    assert backend.calls


def _seed_assessment(client: TestClient) -> dict:  # type: ignore[no-untyped-def]
    project = client.post("/projects", json={"name": "Acme"}).json()
    scope = client.post(
        "/scopes/draft",
        json={"project_id": project["id"], "include": ["https://target.test"]},
    ).json()
    return client.post(
        "/assessments",
        json={"project_id": project["id"], "scope_snapshot_id": scope["id"]},
    ).json()


@pytest.mark.skipif(
    not os.environ.get("MINIMAX_API_KEY"), reason="MINIMAX_API_KEY not set"
)
def test_minimax_smoke_call(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """One real MiniMax call through the governed gateway (smoke only)."""
    from secopent.application.remote_model import DataClassification
    from secopent.domain.common.canonical import utc_now

    app = create_app(create_sqlite_engine(tmp_path / "smoke.db"))
    gateway = app.state.model_gateway
    response = gateway.call(
        "Reply with the single word: pong",
        classification=DataClassification.PUBLIC,
        now=utc_now(),
    )
    assert isinstance(response.text, str)
