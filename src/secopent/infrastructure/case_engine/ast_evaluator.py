# src/secopent/infrastructure/case_engine/ast_evaluator.py
"""Internal AST evaluator for case assertions (§11.3: no Python eval).

Assertions are parsed with the stdlib ``ast`` module and interpreted by walking
a whitelisted set of node types and functions. ``eval``/``exec`` are never
called; attribute access, subscripting, lambdas, comprehensions, and non-
whitelisted calls are all rejected with ``ExpressionError``. An assertion string
therefore cannot escape into arbitrary code execution.

Supported:
- literals (str/int/float/bool/None), list/tuple literals (for ``in``)
- names resolved against the evaluation context
- comparisons ``== != < <= > >= in not in`` (chainable)
- boolean ``and / or / not`` and unary minus
- whitelisted functions: contains, len, matches, starts_with, ends_with,
  equals, lower, upper
"""
from __future__ import annotations

import ast
import operator
from collections.abc import Callable, Mapping
from typing import Any

from secopent.domain.common.errors import DomainError


class ExpressionError(DomainError):
    """Raised when an assertion expression is invalid or uses a disallowed construct."""


def _contains(haystack: Any, needle: Any) -> bool:
    try:
        return needle in haystack
    except TypeError as exc:
        raise ExpressionError(f"contains() unsupported operand: {exc}") from exc


def _matches(pattern: Any, text: Any) -> bool:
    import re

    if not isinstance(pattern, str):
        raise ExpressionError("matches() pattern must be a string")
    try:
        return re.search(pattern, str(text)) is not None
    except re.error as exc:
        raise ExpressionError(f"matches() invalid regex: {exc}") from exc


def _starts_with(text: Any, prefix: Any) -> bool:
    return str(text).startswith(str(prefix))


def _ends_with(text: Any, suffix: Any) -> bool:
    return str(text).endswith(str(suffix))


_FUNCTIONS: dict[str, Callable[..., Any]] = {
    "contains": _contains,
    "len": len,
    "matches": _matches,
    "starts_with": _starts_with,
    "ends_with": _ends_with,
    "equals": lambda a, b: a == b,
    "lower": lambda text: str(text).lower(),
    "upper": lambda text: str(text).upper(),
}

_COMPARE_OPS: dict[type, Callable[[Any, Any], bool]] = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}


def evaluate_expression(expression: str, context: Mapping[str, Any]) -> Any:
    """Safely evaluate an assertion expression against a context mapping."""
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise ExpressionError(f"invalid expression syntax: {exc}") from exc
    return _eval(tree.body, context)


def _eval(node: ast.AST, ctx: Mapping[str, Any]) -> Any:  # noqa: PLR0911, PLR0912
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.List | ast.Tuple):
        return [_eval(elt, ctx) for elt in node.elts]
    if isinstance(node, ast.Name):
        if node.id in ctx:
            return ctx[node.id]
        raise ExpressionError(f"unknown name in expression: {node.id!r}")
    if isinstance(node, ast.BoolOp):
        return _eval_boolop(node, ctx)
    if isinstance(node, ast.UnaryOp):
        return _eval_unary(node, ctx)
    if isinstance(node, ast.Compare):
        return _eval_compare(node, ctx)
    if isinstance(node, ast.Call):
        return _eval_call(node, ctx)
    raise ExpressionError(
        f"disallowed expression construct: {type(node).__name__}"
    )


def _eval_boolop(node: ast.BoolOp, ctx: Mapping[str, Any]) -> Any:
    if isinstance(node.op, ast.And):
        result: Any = True
        for value in node.values:
            result = _eval(value, ctx)
            if not result:
                return result
        return result
    if isinstance(node.op, ast.Or):
        result = False
        for value in node.values:
            result = _eval(value, ctx)
            if result:
                return result
        return result
    raise ExpressionError("disallowed boolean operator")


def _eval_unary(node: ast.UnaryOp, ctx: Mapping[str, Any]) -> Any:
    if isinstance(node.op, ast.Not):
        return not _eval(node.operand, ctx)
    if isinstance(node.op, ast.USub):
        return -_eval(node.operand, ctx)
    raise ExpressionError("disallowed unary operator")


def _eval_compare(node: ast.Compare, ctx: Mapping[str, Any]) -> bool:
    left = _eval(node.left, ctx)
    for op, comparator in zip(node.ops, node.comparators, strict=True):
        op_fn = _COMPARE_OPS.get(type(op))
        if op_fn is None:
            raise ExpressionError(f"disallowed comparison: {type(op).__name__}")
        right = _eval(comparator, ctx)
        try:
            if not op_fn(left, right):
                return False
        except TypeError as exc:
            raise ExpressionError(f"invalid comparison: {exc}") from exc
        left = right
    return True


def _eval_call(node: ast.Call, ctx: Mapping[str, Any]) -> Any:
    if node.keywords:
        raise ExpressionError("keyword arguments are not allowed in assertions")
    if not isinstance(node.func, ast.Name):
        raise ExpressionError("only direct whitelisted function calls are allowed")
    func = _FUNCTIONS.get(node.func.id)
    if func is None:
        raise ExpressionError(f"function not allowed in assertions: {node.func.id!r}")
    args = [_eval(arg, ctx) for arg in node.args]
    try:
        return func(*args)
    except ExpressionError:
        raise
    except Exception as exc:  # noqa: BLE001 - surface any call failure as an expression error
        raise ExpressionError(f"assertion function failed: {exc}") from exc
