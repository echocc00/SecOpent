# src/secopent/interfaces/api/routers/loops.py
"""Loop pause/resume router (spec §6.3, v0.7.7 Task 5).

Human-only control of a ReasoningLoop via PauseControlService:

- ``POST /loops/{loop_id}/pause``  - freeze a running loop (human only);
- ``POST /loops/{loop_id}/resume`` - resume under a human-signed approval.

The service itself enforces the human-only gate (agent -> ApprovalRejected);
this router maps the service errors onto HTTP status codes and reaches the
composed ``PauseControlService`` through ``request.app.state.loop_control``
(mirroring how ``emergency_stop`` reads ``app.state.emergency_stop``).
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from ....application.ports.loop_approval import (
    ApprovalRejected,
    ApprovalRequired,
)
from ....application.reasoning_loop.pause_control import (
    PauseBudgetExceeded,
    PauseControlService,
)
from ....domain.common.errors import DomainError
from ....domain.reasoning_loop.models import LoopId

router = APIRouter(prefix="/loops", tags=["loops"])


class LoopPauseRequest(BaseModel):
    """Body for POST /loops/{id}/pause (human actor required)."""

    model_config = ConfigDict(extra="forbid")

    actor: str
    reason: str
    actor_role: str = "human"


class LoopResumeRequest(BaseModel):
    """Body for POST /loops/{id}/resume (human actor + signed approval)."""

    model_config = ConfigDict(extra="forbid")

    actor: str
    actor_role: str = "human"
    approved_by: str | None = None
    signature: str | None = None
    nonce: str | None = None
    expires_at: datetime | None = None
    modified_context: object | None = None


def _control(request: Request) -> PauseControlService:
    """The composed PauseControlService, or a loud 503 when unconfigured.

    The composition root (``create_app``) is mandatory since the loop service
    is wired onto ``app.state.loop_control``; an unconfigured app fails loudly
    rather than silently reporting a false pause/resume.
    """
    control = getattr(request.app.state, "loop_control", None)
    if not isinstance(control, PauseControlService):
        raise HTTPException(status_code=503, detail="loop control not configured")
    return control


@router.post("/{loop_id}/pause")
def pause_loop(loop_id: str, payload: LoopPauseRequest, request: Request) -> dict[str, str]:
    """Pause a loop (human only; agent -> 403).

    Returns the loop id + phase. Already-paused loops are idempotent (200).
    """
    service = _control(request)
    try:
        state = service.pause(
            loop_id=LoopId(loop_id),
            actor=payload.actor,
            reason=payload.reason,
            actor_role=payload.actor_role,
        )
    except ApprovalRejected as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DomainError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"loop_id": state.loop_id.value, "phase": state.phase.value}


@router.post("/{loop_id}/resume")
def resume_loop(
    loop_id: str, payload: LoopResumeRequest, request: Request
) -> dict[str, object]:
    """Resume a paused loop under a human-signed approval (agent -> 403).

    Missing/empty signature -> 401 (ApprovalRequired); expired pause budget ->
    409; a stopped/terminal loop cannot resume -> 409; unknown loop -> 404.
    """
    service = _control(request)
    try:
        state = service.resume(
            loop_id=LoopId(loop_id),
            actor=payload.actor,
            actor_role=payload.actor_role,
            approved_by=payload.approved_by,
            signature=payload.signature,
            nonce=payload.nonce,
            expires_at=payload.expires_at,
            modified_context=payload.modified_context,
        )
    except ApprovalRejected as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ApprovalRequired as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except PauseBudgetExceeded as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except DomainError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "loop_id": state.loop_id.value,
        "phase": state.phase.value,
        "pause_attempts": state.pause_attempts,
    }
