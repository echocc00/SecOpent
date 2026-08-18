"""PolicyGate: wraps the existing PolicyEngine for ReasoningLoop (spec §6.2).

No new policy logic. Translates a ProposeAction into the PolicyEngine's
``ActionRequest`` and maps the resulting ``PolicyDecision(allowed, reason)``
to a ``GateVerdict``.

Delegates to ``domain.policy.engine.evaluate``:
    evaluate(request, *, scope, mode, approved_risks, approved_capabilities)
        -> PolicyDecision(allowed, reason)

The real ``PolicyDecision`` has only ``allowed`` + ``reason`` (no
``deny_code``), so the gate reuses the reason string as the stable
``GateVerdict.deny_code`` (e.g. "SCOPE_DENIED", "RISK_NOT_APPROVED").
"""
from __future__ import annotations

from collections.abc import Callable

from ...domain.policy.engine import evaluate as engine_evaluate
from ...domain.policy.models import (
    ActionRequest,
    ExecutionMode,
    PolicyDecision,
    RiskClass,
)
from ...domain.reasoning_loop.models import (
    GateVerdict,
    LoopContext,
    ProposeAction,
)
from ...domain.scope.models import ScopeSnapshot
from ..ports.loop_gates import PolicyGate


class PolicyGateImpl(PolicyGate):
    def __init__(
        self,
        *,
        scope: ScopeSnapshot,
        mode: ExecutionMode,
        approved_risks: frozenset[RiskClass],
        approved_capabilities: frozenset[str],
        engine: Callable[..., PolicyDecision] = engine_evaluate,
    ) -> None:
        self._scope = scope
        self._mode = mode
        self._approved_risks = approved_risks
        self._approved_capabilities = approved_capabilities
        self._engine = engine

    def check(self, action: ProposeAction, context: LoopContext) -> GateVerdict:
        request = _action_to_request(action)
        decision = self._engine(
            request,
            scope=self._scope,
            mode=self._mode,
            approved_risks=self._approved_risks,
            approved_capabilities=self._approved_capabilities,
        )
        if decision.allowed:
            return GateVerdict(passed=True, reason=decision.reason)
        return GateVerdict(
            passed=False,
            reason=decision.reason,
            deny_code=decision.reason,
        )


def _action_to_request(action: ProposeAction) -> ActionRequest:
    """Best-effort adapter from a ProposeAction to a PolicyEngine ActionRequest.

    A ProposeAction represents a tool/case action and does not natively carry
    the host/port/risk a policy ``ActionRequest`` needs, so those are read from
    the action's free-form ``parameters`` dict with safe defaults.
    """
    payload = action.payload
    params = payload.get("parameters") or {}
    capability = action.tool_id or action.payload.get("case_id") or "<unknown>"
    target = params.get("host") or params.get("url") or "<unknown>"

    raw_port = params.get("port")
    port = raw_port if isinstance(raw_port, int) else 443

    raw_risk = params.get("risk")
    if isinstance(raw_risk, str):
        try:
            risk = RiskClass(raw_risk)
        except ValueError:
            risk = RiskClass.ACTIVE
    else:
        risk = RiskClass.ACTIVE

    return ActionRequest(
        target=str(target),
        port=port,
        risk=risk,
        capability=str(capability),
    )
