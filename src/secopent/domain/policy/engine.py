from __future__ import annotations

from ..scope.models import ScopeSnapshot
from .models import ActionRequest, ExecutionMode, PolicyDecision, RiskClass


def evaluate(
    request: ActionRequest,
    *,
    scope: ScopeSnapshot,
    mode: ExecutionMode,
    approved_risks: frozenset[RiskClass],
    approved_capabilities: frozenset[str],
) -> PolicyDecision:
    if request.risk is RiskClass.DESTRUCTIVE:
        return PolicyDecision(False, "DESTRUCTIVE_ACTION_DENIED")
    if not scope.includes_port(request.port) or not scope.includes_url(request.target):
        return PolicyDecision(False, "SCOPE_DENIED")
    if request.risk not in approved_risks:
        return PolicyDecision(False, "RISK_NOT_APPROVED")
    if request.risk in {RiskClass.ACTIVE, RiskClass.INTRUSIVE} and (
        request.capability not in approved_capabilities
    ):
        return PolicyDecision(False, "CAPABILITY_NOT_APPROVED")
    return PolicyDecision(True, "ALLOWED")
