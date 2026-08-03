# src/secopent/application/deliverables.py
"""Deliverables contract: structured phase outputs on disk (spec §7).

Adopts Shannon's deliverables convention (rewritten): every execution phase
writes ONE markdown deliverable at a deterministic path
(``deliverables/<phase>_deliverable.md``) plus a scratchpad dir for
intermediate artifacts. Deterministic paths make phase handoffs auditable
and give LLM proposal steps structured context without scraping logs.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ..domain.common.errors import DomainError


class DeliverableValidationError(DomainError):
    """A required deliverable is missing or empty."""


@dataclass(frozen=True, slots=True)
class DeliverablesLayout:
    root: Path

    def deliverable_path(self, phase: str) -> Path:
        return Path(self.root) / "deliverables" / f"{phase}_deliverable.md"

    def scratchpad_dir(self) -> Path:
        return Path(self.root) / "scratchpad"


def write_deliverable(layout: DeliverablesLayout, phase: str, content: str) -> None:
    path = layout.deliverable_path(phase)
    path.parent.mkdir(parents=True, exist_ok=True)
    layout.scratchpad_dir().mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def read_deliverable(layout: DeliverablesLayout, phase: str) -> str:
    return layout.deliverable_path(phase).read_text(encoding="utf-8")


def validate_layout(
    layout: DeliverablesLayout, *, required_phases: Iterable[str]
) -> None:
    for phase in required_phases:
        path = layout.deliverable_path(phase)
        if not path.exists():
            raise DeliverableValidationError(
                f"missing deliverable for phase '{phase}': {path}"
            )
        if not path.read_text(encoding="utf-8").strip():
            raise DeliverableValidationError(
                f"empty deliverable for phase '{phase}': {path}"
            )
