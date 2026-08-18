"""Frozen dataclasses for ReasoningLoop state and data (spec §3)."""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

_LOOP_ID_RE = re.compile(r"^[0-9a-f]{8}$")


@dataclass(frozen=True, slots=True)
class LoopId:
    """Value object identifying one ReasoningLoop instance."""

    value: str

    def __post_init__(self) -> None:
        if not _LOOP_ID_RE.fullmatch(self.value):
            raise ValueError(
                f"LoopId must be 8 lowercase hex chars, got: {self.value!r}"
            )

    @classmethod
    def new(cls) -> LoopId:
        return cls(value=secrets.token_hex(4))
