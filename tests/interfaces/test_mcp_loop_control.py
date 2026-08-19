# tests/interfaces/test_mcp_loop_control.py
"""MCP surface for loop pause/resume (human-only, spec §6.3, v0.7.7 Task 5).

In the MCP layer the caller is always the AGENT, so the loop is NOT controllable
there: the PauseControlService raises ApprovalRejected and ``_guard`` maps it to
a structured HUMAN_REQUIRED result (never a 403 or a crash). This test asserts
the tools are registered and the agent path is rejected at the human boundary.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from secopent.domain.reasoning_loop.models import (
    LoopBudget,
    LoopId,
    LoopPhase,
    LoopState,
)
from secopent.interfaces.api.main import create_app
from secopent.interfaces.mcp import STANDARD_ORCHESTRATION_TOOLS
from secopent.interfaces.mcp.tool_registry import McpToolRegistry


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def reg(app):
    registry = app.state.mcp_tool_registry
    assert isinstance(registry, McpToolRegistry)
    return registry


def _loop(lid: LoopId, *, phase: LoopPhase = LoopPhase.RUNNING) -> LoopState:
    return LoopState(
        loop_id=lid,
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


def test_loop_control_tools_are_standard(app, reg) -> None:  # noqa: ANN001
    assert "loop_pause" in STANDARD_ORCHESTRATION_TOOLS
    assert "loop_resume" in STANDARD_ORCHESTRATION_TOOLS
    assert "loop_pause" in reg
    assert "loop_resume" in reg


def test_agent_pause_is_human_gated(app, reg) -> None:  # noqa: ANN001
    lid = LoopId.new()
    app.state.loop_control._state_repo.save(_loop(lid))  # noqa: SLF001
    result = reg.invoke("loop_pause", loop_id=lid.value, reason="x")
    assert result["status"] == "HUMAN_REQUIRED"
    assert result["action"] == "loop_pause"


def test_agent_resume_is_human_gated(app, reg) -> None:  # noqa: ANN001
    lid = LoopId.new()
    app.state.loop_control._state_repo.save(  # noqa: SLF001
        _loop(lid, phase=LoopPhase.PAUSED)
    )
    result = reg.invoke("loop_resume", loop_id=lid.value, approved_by="cara",
                        signature="sig")
    assert result["status"] == "HUMAN_REQUIRED"
    assert result["action"] == "loop_resume"
