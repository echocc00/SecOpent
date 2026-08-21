# tests/interfaces/api/test_loops_api.py
"""HTTP surface for the ReasoningLoop control plane (spec §6.3, v0.7.7 + v0.7.8).

Covers:

- POST /loops/{id}/pause and POST /loops/{id}/resume (v0.7.7 Task 5);
- GET /loops/{id}   read-only status (v0.7.8 Task 6);
- POST /loops/{id}/stop (v0.7.8 Task 6);
- POST /loops       human-only loop creation (v0.7.8 Task 6).

All run against both the root app (dev proxy) and the /api sub-app
(production). The human-only gate is enforced in the service (agent -> 403)
for pause/resume; stop/create gate the actor_role at the router boundary.
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
    LoopStep,
    PolicyDecision,
    ProposeAction,
)
from secopent.interfaces.api.main import create_app


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    # These are handler SEMANTIC tests (budget override, actor_role gate,
    # mounting). Persistence across sessions is covered by
    # tests/infrastructure/test_realism_loop_persistence.py; here we wire
    # in-memory loop repos so the SQL FK constraint on core_reasoning_loops
    # (assessment_id) does not reject the synthetic assessment ids these
    # tests use. ``_loop_write_ctx`` sees InMemory repos and yields None,
    # so the handler writes through the pre-bound in-memory stores.
    from secopent.application.reasoning_loop.in_memory_state import (
        InMemoryLoopStateRepository,
        InMemoryLoopStepRepository,
    )
    from secopent.application.reasoning_loop.pause_control import (
        PauseControlService,
    )
    from secopent.infrastructure.reasoning_loop.loop_approval import (
        SignedLoopApproval,
    )
    state_repo = InMemoryLoopStateRepository()
    step_repo = InMemoryLoopStepRepository()
    app.state.loop_state_repo = state_repo
    app.state.loop_step_repo = step_repo
    app.state.loop_control = PauseControlService(
        state_repo=state_repo,
        audit=app.state.audit_chain,
        approval=SignedLoopApproval(),
    )
    # The /api sub-app copies app.state during create_app; mirror the swap
    # onto the mounted sub-app so requests under /api/loops see the same
    # in-memory stores.
    for route in app.routes:
        sub = getattr(route, "app", None)
        if hasattr(sub, "state") and hasattr(sub.state, "db"):
            sub.state.loop_state_repo = state_repo
            sub.state.loop_step_repo = step_repo
            sub.state.loop_control = app.state.loop_control
    return TestClient(app)


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


# --------------------------------------------------------------------------
# v0.7.8 Task 6: GET /loops/{id} (read-only status; agent + human callable)
# --------------------------------------------------------------------------


def _seed_step(client: TestClient, lid: LoopId, step_number: int = 1) -> None:
    """Add one recorded step so GET can report a non-zero step_count."""
    step = LoopStep(
        step_id=f"step-seed-{step_number}",
        loop_id=lid,
        step_number=step_number,
        timestamp=datetime(2026, 8, 19, 12, 1, 0, tzinfo=UTC),
        context_hash_before="ctx-hash",
        proposed_action=ProposeAction(
            action_type="run_tool",
            payload={"tool_id": "t1", "parameters": {}},
            rationale="r" * 60,
            confidence=0.5,
        ),
        propose_tokens_used=100,
        propose_latency_ms=50,
        propose_rationale="ok",
        schema_check_passed=True,
        policy_decision=PolicyDecision(verdict="allow", reason="ok"),
        permit_id="permit-1",
        tool_or_case_id="t1",
        execution_result_digest="",
        evidence_refs=(),
        observation_signals=(),
        catalog_class_matched=frozenset(),
        oracle_progressed=False,
        correlation_id="corr-seed",
    )
    client.app.state.loop_step_repo.add(step)


def test_get_loop_status_200(client: TestClient) -> None:
    lid = _loop_id()
    _seed(client, _loop(lid, phase=LoopPhase.RUNNING))
    _seed_step(client, lid)
    resp = client.get(f"/loops/{lid.value}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["loop_id"] == lid.value
    assert body["phase"] == "running"
    assert body["step_count"] == 1
    assert body["context_hash"] == "ctx-hash"
    budget = body["budget_remaining"]
    assert budget["steps"] == 50
    assert budget["tokens"] == 200_000
    assert budget["wall_seconds"] == 1800


def test_get_loop_status_agent_callable_no_gate(client: TestClient) -> None:
    """GET has no actor_role gate: any caller (incl. the agent) reads status."""
    lid = _loop_id()
    _seed(client, _loop(lid))
    resp = client.get(f"/loops/{lid.value}")
    assert resp.status_code == 200
    assert resp.json()["phase"] == "running"


def test_get_loop_status_unknown_404(client: TestClient) -> None:
    resp = client.get("/loops/1234abcd")
    assert resp.status_code == 404


def test_get_loop_mounted_under_api_subapp(client: TestClient) -> None:
    lid = _loop_id()
    _seed(client, _loop(lid))
    resp = client.get(f"/api/loops/{lid.value}")
    assert resp.status_code == 200
    assert resp.json()["phase"] == "running"


# --------------------------------------------------------------------------
# v0.7.8 Task 6: POST /loops/{id}/stop (human-only -> EMERGENCY_STOPPED)
# --------------------------------------------------------------------------


def test_stop_agent_denied_403(client: TestClient) -> None:
    lid = _loop_id()
    _seed(client, _loop(lid))
    resp = client.post(
        f"/loops/{lid.value}/stop",
        json={"actor": "agent-1", "reason": "x", "actor_role": "agent"},
    )
    assert resp.status_code == 403
    assert "human" in resp.json()["detail"].lower()


def test_stop_human_200_emergency_stopped(client: TestClient) -> None:
    lid = _loop_id()
    _seed(client, _loop(lid, phase=LoopPhase.RUNNING))
    resp = client.post(
        f"/loops/{lid.value}/stop", json={"actor": "alice", "reason": "halt"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["loop_id"] == lid.value
    assert body["phase"] == "emergency_stopped"

    # The underlying state is transitioned (a subsequent GET reflects it).
    state = client.app.state.loop_state_repo.get(lid)
    assert state is not None
    assert state.phase is LoopPhase.EMERGENCY_STOPPED


def test_stop_already_stopped_idempotent_200(client: TestClient) -> None:
    lid = _loop_id()
    _seed(client, _loop(lid, phase=LoopPhase.EMERGENCY_STOPPED))
    resp = client.post(
        f"/loops/{lid.value}/stop", json={"actor": "alice", "reason": "again"}
    )
    assert resp.status_code == 200
    assert resp.json()["phase"] == "emergency_stopped"


def test_stop_unknown_loop_404(client: TestClient) -> None:
    resp = client.post(
        "/loops/1234abcd/stop", json={"actor": "alice", "reason": "x"}
    )
    assert resp.status_code == 404


# --------------------------------------------------------------------------
# v0.7.8 Task 6: POST /loops (human-only loop creation)
# --------------------------------------------------------------------------


def test_create_loop_agent_denied_403(client: TestClient) -> None:
    resp = client.post(
        "/loops",
        json={"actor": "agent-1", "assessment_id": "a1", "actor_role": "agent"},
    )
    assert resp.status_code == 403
    assert "human" in resp.json()["detail"].lower()


def test_create_loop_human_201(client: TestClient) -> None:
    resp = client.post(
        "/loops",
        json={"actor": "alice", "assessment_id": "assessment-9", "actor_role": "human"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert "loop_id" in body
    assert LoopId(body["loop_id"])  # valid 8-hex id
    assert body["phase"] == "initializing"

    # The newly created loop is persisted for the rest of the control plane.
    state = client.app.state.loop_state_repo.get(LoopId(body["loop_id"]))
    assert state is not None
    assert state.assessment_id == "assessment-9"
    assert state.phase is LoopPhase.INITIALIZING


def test_create_loop_human_budget_override(client: TestClient) -> None:
    resp = client.post(
        "/loops",
        json={
            "actor": "alice",
            "assessment_id": "assessment-9",
            "actor_role": "human",
            "max_steps": 7,
            "max_wall_seconds": 99,
            "max_total_tokens": 1000,
        },
    )
    assert resp.status_code == 201
    state = client.app.state.loop_state_repo.get(LoopId(resp.json()["loop_id"]))
    assert state is not None
    assert state.budget.max_steps == 7
    assert state.budget.max_wall_seconds == 99
    assert state.budget.max_total_tokens == 1000


def test_create_loop_mounted_under_api_subapp(client: TestClient) -> None:
    resp = client.post(
        "/api/loops",
        json={"actor": "alice", "assessment_id": "assessment-9", "actor_role": "human"},
    )
    assert resp.status_code == 201
    assert resp.json()["phase"] == "initializing"


def test_loops_mounted_under_api_subapp(client: TestClient) -> None:
    lid = _loop_id()
    _seed(client, _loop(lid, phase=LoopPhase.PAUSED))
    resp = client.post(
        f"/api/loops/{lid.value}/pause", json={"actor": "alice", "reason": "x"}
    )
    assert resp.status_code == 200
    assert resp.json()["phase"] == "paused"
