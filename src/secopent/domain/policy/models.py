# src/secopent/domain/policy/models.py
from __future__ import annotations
from dataclasses import dataclass
from enum import StrEnum


class RiskClass(StrEnum):
    PASSIVE = "passive"
    LOW = "low"
    ACTIVE = "active"
    INTRUSIVE = "intrusive"
    DESTRUCTIVE = "destructive"


class ExecutionMode(StrEnum):
    APPROVAL = "approval"
    SCOPE_AUTOPILOT = "scope_autopilot"


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True, slots=True)
class ActionRequest:
    target: str
    port: int
    risk: RiskClass
    capability: str
