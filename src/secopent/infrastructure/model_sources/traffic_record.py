# src/secopent/infrastructure/model_sources/traffic_record.py
"""Traffic-recording draft path (§11.9 undocumented path, LLM proposes only).

When there is no API spec, a passive proxy records request traffic; the recorder
clusters requests by (method, path) into transitions and asks an LLM gateway to
*propose* a state machine. The result is an LLM_PROPOSED AppModel - per the
LLM边界 the LLM only drafts; a human must validate and sign it (ModelBuilder).
The LLM gateway is injected (RemoteModelGateway in M5; a mock in tests).
"""
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from secopent.domain.appmodel.lifecycle import AppModelStatus
from secopent.domain.appmodel.models import AppModel, Transition


@dataclass(frozen=True, slots=True)
class RecordedRequest:
    """A single recorded HTTP request (method + path + observed response fields)."""

    method: str
    path: str
    response_fields: tuple[str, ...] = ()


@runtime_checkable
class ModelDraftGateway(Protocol):
    """LLM gateway that proposes states for a set of endpoints (drafts only)."""

    def draft_states(self, endpoints: Sequence[str]) -> tuple[str, ...]: ...


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "app"


class TrafficRecorder:
    """Cluster recorded traffic and draft an LLM_PROPOSED AppModel."""

    source_type = "traffic"

    def __init__(self, llm: ModelDraftGateway | None = None) -> None:
        self._llm = llm

    def cluster(self, requests: Sequence[RecordedRequest]) -> tuple[Transition, ...]:
        """De-duplicate requests into transitions keyed by (method, path)."""
        seen: set[tuple[str, str]] = set()
        transitions: list[Transition] = []
        for req in requests:
            method = req.method.upper()
            key = (method, req.path)
            if key in seen:
                continue
            seen.add(key)
            op_id = _slug(f"{method}-{req.path}") or f"op{len(transitions)}"
            transitions.append(
                Transition(
                    id=op_id,
                    from_state="default",
                    to_state="default",
                    endpoint=f"{method} {req.path}",
                )
            )
        return tuple(transitions)

    def to_draft(self, app_name: str, requests: Sequence[RecordedRequest]) -> AppModel:
        """Cluster traffic and (optionally) LLM-draft states; status LLM_PROPOSED."""
        transitions = self.cluster(requests)
        endpoints = [t.endpoint for t in transitions]
        if self._llm is not None and endpoints:
            states = tuple(self._llm.draft_states(endpoints)) or ("default",)
        else:
            states = ("default",)
        return AppModel(
            app_id=_slug(app_name),
            version="0.0.1",
            states=states,
            transitions=transitions,
            status=AppModelStatus.LLM_PROPOSED,
        )
