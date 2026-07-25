"""TDD tests for the case-engine AST evaluator (M2 Task 7, §11.3 no-eval).

Case assertions are evaluated by an internal AST walker built on Python's
``ast`` module - we parse the expression and interpret a whitelisted set of node
types and functions ourselves. ``eval``/``exec`` are never called, attribute
access and arbitrary calls are rejected, so an assertion string cannot escape
into arbitrary code execution.
"""
from __future__ import annotations

import pytest

from secopent.infrastructure.case_engine.ast_evaluator import (
    ExpressionError,
    evaluate_expression,
)


def test_equality() -> None:
    assert evaluate_expression("status_code == 200", {"status_code": 200}) is True
    assert evaluate_expression("status_code == 200", {"status_code": 404}) is False


def test_ordering_comparisons() -> None:
    ctx = {"status_code": 204}
    assert evaluate_expression("status_code >= 200", ctx) is True
    assert evaluate_expression("status_code < 300", ctx) is True
    assert evaluate_expression("status_code > 300", ctx) is False


def test_boolean_and_or_not() -> None:
    ctx = {"status_code": 204}
    assert evaluate_expression("status_code >= 200 and status_code < 300", ctx) is True
    assert evaluate_expression("status_code == 404 or status_code == 204", ctx) is True
    assert evaluate_expression("not (status_code == 404)", ctx) is True


def test_contains_function() -> None:
    assert evaluate_expression("contains(body, 'admin')", {"body": "welcome admin"}) is True
    assert evaluate_expression("contains(body, 'root')", {"body": "welcome admin"}) is False


def test_len_function() -> None:
    assert evaluate_expression("len(body) > 0", {"body": "x"}) is True
    assert evaluate_expression("len(body) == 0", {"body": ""}) is True


def test_matches_regex_function() -> None:
    ctx = {"body": "token=abc123"}
    assert evaluate_expression(r"matches('token=[a-z0-9]+', body)", ctx) is True
    assert evaluate_expression(r"matches('^nomatch$', body)", ctx) is False


def test_in_operator_with_list() -> None:
    assert evaluate_expression("status_code in [200, 204, 301]", {"status_code": 204}) is True
    assert evaluate_expression("status_code in [200, 301]", {"status_code": 404}) is False


def test_string_literals_and_concatenation_context() -> None:
    assert evaluate_expression("title == 'OK'", {"title": "OK"}) is True


def test_unknown_name_raises() -> None:
    with pytest.raises(ExpressionError):
        evaluate_expression("undefined_var == 1", {})


def test_arbitrary_call_rejected() -> None:
    with pytest.raises(ExpressionError):
        evaluate_expression("__import__('os').system('id')", {})


def test_attribute_access_rejected() -> None:
    with pytest.raises(ExpressionError):
        evaluate_expression("body.upper", {"body": "x"})


def test_non_whitelisted_function_rejected() -> None:
    with pytest.raises(ExpressionError):
        evaluate_expression("eval('1+1')", {})


def test_syntax_error_raises() -> None:
    with pytest.raises(ExpressionError):
        evaluate_expression("status_code ===", {"status_code": 1})
