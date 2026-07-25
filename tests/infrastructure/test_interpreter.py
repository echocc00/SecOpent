"""TDD tests for the case DSL interpreter (M2 Task 7, §11.3).

The interpreter executes a case's DSL steps against an injected ExecutionContext
(a mock HTTP backend in tests) and evaluates the assertions with the no-eval AST
evaluator. It enforces the §11.3 constraints: deny-listed actions (Shell /
dynamic import / out-of-scope target) are rejected, and foreach/retry/wait must
carry bounds within hard caps.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from secopent.domain.cases.models import CaseAssertion, CaseDefinition, CaseStep
from secopent.domain.policy.models import RiskClass
from secopent.infrastructure.case_engine.interpreter import (
    CaseInterpreter,
    ExecutionContext,
    HttpResponse,
    InterpreterError,
)


@dataclass
class MockHttp:
    response: HttpResponse
    calls: list[dict[str, Any]] = field(default_factory=list)

    def http_request(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> HttpResponse:
        self.calls.append({"method": method, "url": url})
        return self.response


def _case(*steps: CaseStep, assertions: tuple[CaseAssertion, ...] = ()) -> CaseDefinition:
    return CaseDefinition(
        id="c",
        version="1.0.0",
        author="a",
        risk=RiskClass.INTRUSIVE,
        target_type="http",
        schema="s",
        steps=tuple(steps),
        assertions=assertions,
    )


def _http_step(url: str = "https://x.test/", method: str = "GET") -> CaseStep:
    return CaseStep(id="req1", action="http.request", spec={"url": url, "method": method})


def test_http_request_and_passing_assertion() -> None:
    ctx = MockHttp(response=HttpResponse(status_code=200, body="welcome admin", headers={}))
    case = _case(
        _http_step(),
        assertions=(CaseAssertion(id="a1", expression="status_code == 200"),),
    )
    result = CaseInterpreter(ctx).run(case)
    assert result.passed is True
    assert result.assertion_results["a1"] is True
    assert ctx.calls[0]["method"] == "GET"


def test_failing_assertion_marks_not_passed() -> None:
    ctx = MockHttp(response=HttpResponse(status_code=404, body="nope", headers={}))
    case = _case(
        _http_step(),
        assertions=(CaseAssertion(id="a1", expression="status_code == 200"),),
    )
    result = CaseInterpreter(ctx).run(case)
    assert result.passed is False
    assert result.assertion_results["a1"] is False


def test_all_assertions_must_pass() -> None:
    ctx = MockHttp(response=HttpResponse(status_code=200, body="admin", headers={}))
    case = _case(
        _http_step(),
        assertions=(
            CaseAssertion(id="a1", expression="status_code == 200"),
            CaseAssertion(id="a2", expression="contains(body, 'root')"),  # false
        ),
    )
    result = CaseInterpreter(ctx).run(case)
    assert result.passed is False


def test_extract_regex_feeds_assertion() -> None:
    ctx = MockHttp(response=HttpResponse(status_code=200, body="token=abc123", headers={}))
    extract = CaseStep(
        id="ex1",
        action="extract.regex",
        spec={"source": "body", "pattern": r"token=([a-z0-9]+)", "var": "tok"},
    )
    case = _case(
        _http_step(),
        extract,
        assertions=(CaseAssertion(id="a1", expression="tok == 'abc123'"),),
    )
    result = CaseInterpreter(ctx).run(case)
    assert result.passed is True


def test_shell_action_rejected() -> None:
    case = _case(CaseStep(id="s", action="shell.exec", spec={"cmd": "id"}))
    with pytest.raises(InterpreterError):
        CaseInterpreter(MockHttp(HttpResponse(200, "", {}))).run(case)


def test_out_of_scope_target_rejected() -> None:
    case = _case(CaseStep(id="s", action="http.request", spec={"target_out_of_scope": True}))
    with pytest.raises(InterpreterError):
        CaseInterpreter(MockHttp(HttpResponse(200, "", {}))).run(case)


def test_unbounded_foreach_rejected() -> None:
    case = _case(CaseStep(id="s", action="foreach", spec={"items": "targets"}))
    with pytest.raises(InterpreterError):
        CaseInterpreter(MockHttp(HttpResponse(200, "", {}))).run(case)


def test_foreach_bound_above_cap_rejected() -> None:
    case = _case(CaseStep(id="s", action="foreach", spec={"items": "targets", "limit": 100000}))
    with pytest.raises(InterpreterError):
        CaseInterpreter(MockHttp(HttpResponse(200, "", {}))).run(case)


def test_wait_above_cap_rejected() -> None:
    case = _case(CaseStep(id="s", action="wait", spec={"seconds": 100000}))
    with pytest.raises(InterpreterError):
        CaseInterpreter(MockHttp(HttpResponse(200, "", {}))).run(case)


def test_dynamic_import_rejected() -> None:
    case = _case(CaseStep(id="s", action="import", spec={"module": "os"}))
    with pytest.raises(InterpreterError):
        CaseInterpreter(MockHttp(HttpResponse(200, "", {}))).run(case)


def test_interpreter_accepts_execution_context_protocol() -> None:
    assert isinstance(MockHttp(HttpResponse(200, "", {})), ExecutionContext)
