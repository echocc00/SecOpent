# src/secopent/application/prompt_injection.py
"""PromptInjectionGuard: isolate untrusted target output from control (§12).

Target output (web pages, banners, tool output, vulnerability descriptions) is
UNTRUSTED and may contain instructions aimed at the agent. The agent affects the
system only via structured ``AgentAction``s, and an action can never touch a
protected resource (scope/policy/plan/approval/secret/case_status/permit/
capability) or use a non-allowlisted (additive-only) action type. Therefore a
prompt injection in target output cannot change the Plan, Scope, approval, etc.
``sanitize`` additionally strips control characters (defense in depth).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..domain.common.errors import DomainError

# Resources untrusted content must never influence.
PROTECTED_TARGETS: frozenset[str] = frozenset(
    {
        "scope",
        "policy",
        "plan",
        "approval",
        "secret",
        "case_status",
        "permit",
        "capability",
    }
)

# The only action types the agent may propose - all additive, none privileged.
ALLOWED_ACTIONS: frozenset[str] = frozenset(
    {"add_observation", "add_finding", "request_coverage", "annotate"}
)

# ASCII control characters to strip (keep tab \t and newline \n).
_KEEP_WHITESPACE = {"\t", "\n"}


class InjectionBlocked(DomainError):
    """Raised when an action tries to touch a protected resource or type."""


@dataclass(frozen=True, slots=True)
class UntrustedContent:
    """A blob of untrusted target output, explicitly flagged."""

    source: str
    text: str
    untrusted: bool = True


@dataclass(frozen=True, slots=True)
class AgentAction:
    """A structured action the agent proposes (validated before any effect)."""

    action_type: str
    target: str
    payload: dict[str, object] = field(default_factory=dict)


class PromptInjectionGuard:
    """Mark untrusted content and gate every agent action."""

    def mark_untrusted(self, source: str, text: str) -> UntrustedContent:
        """Wrap target output as explicitly untrusted."""
        return UntrustedContent(source=source, text=text)

    def validate_action(self, action: AgentAction) -> AgentAction:
        """Reject privileged action types and any action on a protected target."""
        if action.action_type not in ALLOWED_ACTIONS:
            raise InjectionBlocked(
                f"action type not allowed: {action.action_type!r}"
            )
        if action.target in PROTECTED_TARGETS:
            raise InjectionBlocked(
                f"cannot modify protected resource: {action.target!r}"
            )
        return action

    def action_from_untrusted(
        self,
        content: UntrustedContent,
        *,
        action_type: str,
        target: str,
        payload: dict[str, object] | None = None,
    ) -> AgentAction:
        """Build and validate an action derived from untrusted content.

        The content's provenance never grants privilege: the resulting action is
        validated like any other, so untrusted input cannot reach a protected
        target.
        """
        safe_payload = dict(payload or {})
        safe_payload.setdefault("_untrusted_source", content.source)
        action = AgentAction(action_type=action_type, target=target, payload=safe_payload)
        return self.validate_action(action)

    @staticmethod
    def sanitize(text: str) -> str:
        """Strip control characters (keep printable text + tab/newline)."""
        return "".join(
            ch for ch in text if ch in _KEEP_WHITESPACE or ord(ch) >= 32
        )
