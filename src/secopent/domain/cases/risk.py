# src/secopent/domain/cases/risk.py
"""Static case risk computation (§11.6) - the deterministic publish gate input.

Computes a case's action risk from its DSL steps:

- GET/HEAD                          -> Low
- crawl / scan / bounded foreach    -> Active
- credential / upload / timing / OAST -> Intrusive
- Shell / unbounded loop / out-of-scope target -> deny (``None``)

The aggregate risk is the maximum over all steps; any deny pattern denies the
whole case. The RiskAnalyzer (application) compares this to the declared risk
and blocks publish when the declaration understates the computed risk.
"""
from __future__ import annotations

from ..common.errors import DomainError
from ..policy.models import RiskClass
from .models import CaseDefinition, CaseStep

# Risk ladder ordering (higher = more intrusive).
_RISK_RANK: dict[RiskClass, int] = {
    RiskClass.PASSIVE: 0,
    RiskClass.LOW: 1,
    RiskClass.ACTIVE: 2,
    RiskClass.INTRUSIVE: 3,
    RiskClass.DESTRUCTIVE: 4,
}

# Actions that iterate/sleep and therefore MUST carry a hard bound.
_BOUNDED_VERBS = {"foreach", "retry", "wait"}
# Spec keys that constitute a hard bound on a iterating/waiting action.
_BOUND_KEYS = {"limit", "max", "cap", "count", "window"}
# Writing HTTP methods escalate beyond passive GET/HEAD.
_WRITING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}
# Spec markers that make a step intrusive.
_INTRUSIVE_MARKERS = {"credential", "upload", "time_based", "timing"}


class RiskPublishDenied(DomainError):
    """Raised when a case uses a deny-listed pattern (Shell/unbounded/oos)."""


class RiskUndeclared(DomainError):
    """Raised when a case's declared risk is below its computed risk."""


def risk_rank(risk: RiskClass) -> int:
    """Return the ladder rank of a RiskClass (higher = more intrusive)."""
    return _RISK_RANK[risk]


def _verb(action: str) -> str:
    return action.rsplit(".", 1)[-1].lower()


def _has_bound(spec: dict[str, object]) -> bool:
    return any(spec.get(key) for key in _BOUND_KEYS)


def step_risk(step: CaseStep) -> RiskClass | None:
    """Compute one step's risk; ``None`` means the step must never publish."""
    action = step.action.lower()
    verb = _verb(step.action)
    spec = step.spec

    # --- deny patterns (never publishable) ---
    if "shell" in action or spec.get("shell") is True:
        return None
    if verb in {"exec", "eval", "import"} or spec.get("dynamic_import"):
        return None
    if verb in _BOUNDED_VERBS and not _has_bound(spec):
        return None
    if spec.get("target_out_of_scope") is True:
        return None

    # --- intrusive ---
    if action.startswith("oast") or spec.get("oast"):
        return RiskClass.INTRUSIVE
    if any(spec.get(marker) for marker in _INTRUSIVE_MARKERS):
        return RiskClass.INTRUSIVE

    # --- active ---
    if verb in {"crawl", "scan", "foreach"} or spec.get("crawl"):
        return RiskClass.ACTIVE
    method = str(spec.get("method", "")).upper()
    if method in _WRITING_METHODS:
        return RiskClass.ACTIVE

    # --- low (passive GET/HEAD and everything else benign) ---
    return RiskClass.LOW


def compute_risk(case: CaseDefinition) -> RiskClass | None:
    """Compute the case's aggregate risk; ``None`` if any step is deny-listed."""
    risks: list[RiskClass] = []
    for step in case.steps:
        risk = step_risk(step)
        if risk is None:
            return None
        risks.append(risk)
    if not risks:
        return RiskClass.LOW
    return max(risks, key=risk_rank)


def validate_declared_risk(case: CaseDefinition) -> None:
    """Raise if the case's declared risk understates its computed risk."""
    computed = compute_risk(case)
    if computed is None:
        raise RiskPublishDenied(
            f"case {case.id} uses a deny-listed pattern (Shell / unbounded loop / "
            "out-of-scope target) and cannot be published"
        )
    if risk_rank(case.risk) < risk_rank(computed):
        raise RiskUndeclared(
            f"case {case.id} declared risk {case.risk.value} is below the computed "
            f"risk {computed.value}"
        )
