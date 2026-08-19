"""SchemaGate: Pydantic-strict validation for ProposeAction (spec §6.1).

The gate runs AGAINST the dict form (not the validated Pydantic model) so
that LLM-emitted junk cannot bypass by being malformed-but-shape-valid.
"""
from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from ...domain.reasoning_loop.models import (
    GateVerdict,
    LoopActionType,
    LoopContext,
    ProposeAction,
)
from ..ports.loop_gates import SchemaGate


class SchemaGateImpl(SchemaGate):
    """Validates ProposeAction-shaped objects against the strict schema.

    Accepts either a ``ProposeAction`` instance or a Pydantic BaseModel with
    the same field shape (so a stub in tests can exercise the gate with
    deliberate-invalid inputs).
    """

    _ALLOWED_ACTION_TYPES = frozenset({
        "run_tool", "run_case", "request_peer",
        "request_oracle", "request_chain", "abort_step",
    })

    _REQUIRED_PAYLOAD_KEYS: dict[str, frozenset[str]] = {
        "run_tool": frozenset({"tool_id", "parameters"}),
        "run_case": frozenset({"case_id", "parameters"}),
        "request_peer": frozenset({"peer_name", "instruction"}),
        "request_oracle": frozenset({"candidate_id"}),
        "request_chain": frozenset({"hypothesis_id"}),
        "abort_step": frozenset(),
    }

    def check(self, action: Any, context: LoopContext) -> GateVerdict:
        try:
            if isinstance(action, ProposeAction):
                data: dict[str, Any] = action.model_dump()
            else:
                raw: Any = action.model_dump() if hasattr(action, "model_dump") else None
                if not isinstance(raw, dict):
                    return GateVerdict(
                        passed=False,
                        reason="not a pydantic-shaped action",
                        deny_code="SCHEMA_NOT_PYDANTIC",
                    )
                data = raw

            # Per-action-type payload key check FIRST, on the raw dict. The
            # strict ProposeAction re-validation below would otherwise surface
            # a value_error that we'd have to re-derive into
            # SCHEMA_MISSING_PAYLOAD_KEYS; checking here keeps that deny_code
            # explicit and stable.
            action_type = data.get("action_type")
            if action_type in self._REQUIRED_PAYLOAD_KEYS:
                required = self._REQUIRED_PAYLOAD_KEYS[action_type]
                payload = data.get("payload", {})
                missing = required - set(payload.keys())
                if missing:
                    return GateVerdict(
                        passed=False,
                        reason=(
                            f"action_type={action_type!r} missing payload "
                            f"keys {sorted(missing)}"
                        ),
                        deny_code="SCHEMA_MISSING_PAYLOAD_KEYS",
                    )

            # Now strict-revalidate the whole payload.
            validated: ProposeAction
            try:
                validated = ProposeAction.model_validate(data)
            except ValidationError as exc:
                first_err = exc.errors()[0]
                err_type = first_err["type"]
                loc = str(first_err.get("loc", []))
                if err_type in ("literal_error", "enum") and "action_type" in loc:
                    return GateVerdict(
                        passed=False,
                        reason=f"action_type {data.get('action_type')!r} not allowed",
                        deny_code="SCHEMA_INVALID_ACTION_TYPE",
                    )
                if err_type == "extra_forbidden":
                    return GateVerdict(
                        passed=False,
                        reason=f"extra field not permitted at {loc}",
                        deny_code="SCHEMA_EXTRA_FIELDS",
                    )
                if "rationale" in loc:
                    return GateVerdict(
                        passed=False,
                        reason="rationale length out of range",
                        deny_code="SCHEMA_RATIONALE_TOO_SHORT",
                    )
                return GateVerdict(
                    passed=False,
                    reason=str(first_err["msg"]),
                    deny_code="SCHEMA_VALIDATION_FAILED",
                )

            # Shape passed: now check references against the LoopContext.
            # The proposer may only route work to capabilities/hypotheses that
            # actually exist in context, never to hallucinated ones.
            if validated.action_type is LoopActionType.RUN_TOOL:
                tool_id = validated.payload.get("tool_id")
                known = {c.capability_id for c in context.available_tools}
                if tool_id not in known:
                    return GateVerdict(
                        passed=False,
                        reason=f"tool_id {tool_id!r} not in available_tools",
                        deny_code="SCHEMA_UNKNOWN_TOOL",
                    )
            if validated.action_type is LoopActionType.REQUEST_CHAIN:
                hypothesis_id = validated.payload.get("hypothesis_id")
                known_hyp = {h.hypothesis_id for h in context.chain_hypotheses_pending}
                if hypothesis_id not in known_hyp:
                    return GateVerdict(
                        passed=False,
                        reason=f"hypothesis_id {hypothesis_id!r} not pending",
                        deny_code="SCHEMA_UNKNOWN_HYPOTHESIS",
                    )

            return GateVerdict(passed=True, reason="schema_ok")
        except Exception as exc:  # belt-and-braces; gate MUST always return a verdict
            return GateVerdict(
                passed=False,
                reason=f"schema gate crashed: {exc!r}",
                deny_code="SCHEMA_INTERNAL_ERROR",
            )
