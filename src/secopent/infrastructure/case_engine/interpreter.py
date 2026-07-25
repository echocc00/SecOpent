# src/secopent/infrastructure/case_engine/interpreter.py
"""Case DSL interpreter (§11.3): execute steps + evaluate assertions, no eval.

Executes a case's DSL steps against an injected ``ExecutionContext`` (a real
scoped HTTP/DNS/OAST backend in production, a mock in tests) and evaluates the
assertions with the no-eval AST evaluator. The §11.3 constraints are enforced:

- deny-listed actions (Shell / dynamic import / out-of-scope target / unbounded
  loop) are rejected before anything executes;
- ``foreach``/``retry``/``wait`` must carry bounds within hard caps;
- assertions are interpreted by the internal AST, never Python ``eval``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from secopent.domain.cases.models import CaseDefinition, CaseStep
from secopent.domain.cases.risk import compute_risk
from secopent.domain.common.errors import DomainError

from .ast_evaluator import ExpressionError, evaluate_expression

# Hard caps on iterating/waiting actions (§11.3).
FOREACH_LIMIT_CAP = 100
RETRY_LIMIT_CAP = 10
WAIT_SECONDS_CAP = 300

# Control-flow verbs that iterate/wait but do not themselves hit the network.
_CONTROL_VERBS = {"foreach", "retry", "wait", "condition"}


class InterpreterError(DomainError):
    """Raised when a case violates a DSL constraint or an action is unsupported."""


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """Result of an ``http.request`` action."""

    status_code: int
    body: str
    headers: dict[str, str]


@runtime_checkable
class ExecutionContext(Protocol):
    """The scoped execution surface a case runs against (injected; mockable)."""

    def http_request(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> HttpResponse: ...


@dataclass
class InterpreterResult:
    """Outcome of a case run: per-assertion results + the variable store."""

    passed: bool
    assertion_results: dict[str, bool] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)


def _verb(step: CaseStep) -> str:
    return step.action.rsplit(".", 1)[-1].lower()


class CaseInterpreter:
    """Execute a case's steps against an ExecutionContext and check assertions."""

    def __init__(self, context: ExecutionContext) -> None:
        self._ctx = context

    def run(self, case: CaseDefinition) -> InterpreterResult:
        """Run the case; raise InterpreterError on any DSL-constraint violation."""
        if compute_risk(case) is None:
            raise InterpreterError(
                f"case {case.id} uses a deny-listed action (Shell / dynamic import / "
                "out-of-scope target / unbounded loop) and cannot run"
            )
        store: dict[str, Any] = {}
        for step in case.steps:
            self._check_caps(step)
            self._execute_step(step, store)

        assertion_results: dict[str, bool] = {}
        for assertion in case.assertions:
            try:
                assertion_results[assertion.id] = bool(
                    evaluate_expression(assertion.expression, store)
                )
            except ExpressionError:
                assertion_results[assertion.id] = False
        passed = all(assertion_results.values())
        return InterpreterResult(
            passed=passed, assertion_results=assertion_results, context=store
        )

    def _check_caps(self, step: CaseStep) -> None:
        """Enforce hard caps on foreach/retry/wait bounds."""
        verb = _verb(step)
        if verb == "foreach":
            limit = step.spec.get("limit")
            if isinstance(limit, int) and limit > FOREACH_LIMIT_CAP:
                raise InterpreterError(
                    f"foreach limit {limit} exceeds cap {FOREACH_LIMIT_CAP}"
                )
        elif verb == "retry":
            retries = step.spec.get("limit") or step.spec.get("max")
            if isinstance(retries, int) and retries > RETRY_LIMIT_CAP:
                raise InterpreterError(
                    f"retry count {retries} exceeds cap {RETRY_LIMIT_CAP}"
                )
        elif verb == "wait":
            seconds = step.spec.get("seconds")
            if isinstance(seconds, int) and seconds > WAIT_SECONDS_CAP:
                raise InterpreterError(
                    f"wait {seconds}s exceeds cap {WAIT_SECONDS_CAP}s"
                )

    def _execute_step(self, step: CaseStep, store: dict[str, Any]) -> None:
        verb = _verb(step)
        if verb == "request" and step.action.lower().startswith("http"):
            self._execute_http(step, store)
        elif verb == "regex" and step.action.lower().startswith("extract"):
            self._execute_extract_regex(step, store)
        elif verb in _CONTROL_VERBS:
            return  # control flow: bounds already validated; no network effect here
        else:
            raise InterpreterError(
                f"unsupported action in this interpreter: {step.action}"
            )

    def _execute_http(self, step: CaseStep, store: dict[str, Any]) -> None:
        url = str(step.spec.get("url") or "")
        if not url:
            url = str(step.spec.get("base_url", "")) + str(step.spec.get("path", ""))
        method = str(step.spec.get("method", "GET")).upper()
        response = self._ctx.http_request(method=method, url=url)
        store["status_code"] = response.status_code
        store["body"] = response.body
        store["headers"] = response.headers
        store[step.id] = response

    def _execute_extract_regex(self, step: CaseStep, store: dict[str, Any]) -> None:
        source = store.get(str(step.spec.get("source", "")), "")
        pattern = str(step.spec.get("pattern", ""))
        var = str(step.spec.get("var", ""))
        if not var:
            raise InterpreterError("extract.regex requires a 'var' to store the capture")
        try:
            match = re.search(pattern, str(source))
        except re.error as exc:
            raise InterpreterError(f"extract.regex invalid pattern: {exc}") from exc
        if match is None:
            store[var] = ""
        elif match.groups():
            store[var] = match.group(1)
        else:
            store[var] = match.group(0)
