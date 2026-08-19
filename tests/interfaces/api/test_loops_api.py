# tests/interfaces/api/test_loops_api.py
"""HTTP surface for human-only loop pause/resume (spec §6.3, v0.7.7 Task 5).

Covers POST /loops/{id}/pause and POST /loops/{id}/resume on both the root app
(dev proxy) and the /api sub-app (production). The human-only gate is enforced
in the service (agent -> 403); the router maps the service errors onto HTTP.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from secopent.domain.reasoning_loop.models import (
    LoopBudget,
    LoopId,
    LoopPhase,
    LoopState,
)
from secopent.interfaces.api.main import create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def _loop(loop_id: LoopId, *, phase: LoopPhase = LoopPhase.RUNNING) -> LoopState:
    return LoopState(
        loop_id=loop_id,
        assessment_id="assessment-1",
        phase=phase,
        policy_snapshot="policy-snap",
        budget=LoopBudget.default(),
        context_hash="ctx-hash",
        catalog_required_remaining=frozenset(),
        catalog_required_executed=frozenset(),
        consecutive_no_signal=0,
        consecutive_policy_rejected=0,
        started_at=datetime(2026, 8, 19, 12, 0, 0, tzinfo=UTC),
        last_step_at=None,
        paused_at=(
            datetime(2026, 8, 19, 12, 0, 0, tzinfo=UTC)
            if phase is LoopPhase.PAUSED
            else None
        ),
    )


def _seed(client: TestClient, loop: LoopState) -> None:
    service = client.app.state.loop_control
    service._state_repo.save(loop)  # noqa: SLF001 - test preset, not prod path


def _loop_id() -> LoopId:
    return LoopId.new()


def test_pause_agent_denied_403(client: TestClient) -> None:
    lid = _loop_id()
    _seed(client, _loop(lid))
    resp = client.post(
        f"/loops/{lid.value}/pause", json={"actor": "agent-1", "reason": "x",
                                           "actor_role": "agent"}
    )
    assert resp.status_code == 403
    assert "human" in resp.json()["detail"].lower()


def test_pause_human_200_sets_paused_and_audits(client: TestClient) -> None:
    lid = _loop_id()
    _seed(client, _loop(lid))
    resp = client.post(
        f"/loops/{lid.value}/pause", json={"actor": "alice", "reason": "review"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["loop_id"] == lid.value
    assert body["phase"] == "paused"

    # The resumed-loop service recorded a loop.paused audit event on the chain.
    from secopent.application.reasoning_loop.audit import LOOP_PAUSED

    events = client.app.state.audit_chain.events()
    assert any(
        e.action == LOOP_PAUSED and e.resource_id == lid.value for e in events
    )


def test_pause_unknown_loop_404(client: TestClient) -> None:
    resp = client.post(
        "/loops/1234abcd/pause", json={"actor": "alice", "reason": "x"}
    )
    assert resp.status_code == 404


def test_resume_agent_denied_403(client: TestClient) -> None:
    lid = _loop_id()
    _seed(client, _loop(lid, phase=LoopPhase.PAUSED))
    resp = client.post(
        f"/loops/{lid.value}/resume",
        json={"actor": "agent-1", "actor_role": "agent"},
    )
    assert resp.status_code == 403


def test_resume_human_200_with_signature(client: TestClient) -> None:
    lid = _loop_id()
    _seed(client, _loop(lid, phase=LoopPhase.PAUSED))
    resp = client.post(
        f"/loops/{lid.value}/resume",
        json={"actor": "bob", "approved_by": "cara", "signature": "sig-123"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["loop_id"] == lid.value
    assert body["phase"] == "resumed"
    assert body["pause_attempts"] == 1


def test_resume_missing_signature_401(client: TestClient) -> None:
    lid = _loop_id()
    _seed(client, _loop(lid, phase=LoopPhase.PAUSED))
    resp = client.post(
        f"/loops/{lid.value}/resume", json={"actor": "bob"}
    )
    assert resp.status_code == 401


def test_resume_stopped_loop_409(client: TestClient) -> None:
    lid = _loop_id()
    _seed(client, _loop(lid, phase=LoopPhase.COMPLETED))
    resp = client.post(
        f"/loops/{lid.value}/resume",
        json={"actor": "bob", "approved_by": "cara", "signature": "sig"},
    )
    assert resp.status_code == 409


def test_pause_already_paused_idempotent_200(client: TestClient) -> None:
    lid = _loop_id()
    _seed(client, _loop(lid, phase=LoopPhase.PAUSED))
    resp = client.post(
        f"/loops/{lid.value}/pause", json={"actor": "alice", "reason": "again"}
    )
    assert resp.status_code == 200
    assert resp.json()["phase"] == "paused"


def test_loops_mounted_under_api_subapp(client: TestClient) -> None:
    lid = _loop_id()
    _seed(client, _loop(lid, phase=LoopPhase.PAUSED))
    resp = client.post(
        f"/api/loops/{lid.value}/pause", json={"actor": "alice", "reason": "x"}
    )
    assert resp.status_code == 200
    assert resp.json()["phase"] == "paused"
