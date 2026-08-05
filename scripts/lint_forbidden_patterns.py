#!/usr/bin/env python3
"""Forbidden-pattern linter (v0.3.0 T1).

Encodes the invariants whose violation produced the v3/v4/v5 incident class
(see docs/architecture/postmortems/v0.2.0-implicit-boundaries.md):

  R1  no raw ``threading.Thread`` in API routers - use FastAPI
      BackgroundTasks (v3 race class).
  R2  no ``.open_session()`` outside sanctioned modules - long-lived
      background work must reuse the caller's session / UnitOfWork instead of
      opening fresh connections (v4 hot-path new-connection class).
  R3  audit ``.record(...)`` calls in daemon-touching modules must thread
      ``session=`` - a record() without the caller's session opens its own
      SQLite connection and contends for the WAL write lock (v5 leak class).

Usage:
    python scripts/lint_forbidden_patterns.py [--root PATH]

``--root`` points at a tree shaped like ``src/secopent`` (the self-tests use
a tmp tree); the default is the real source tree. Exits 0 when clean and 1
on violations (each printed as ``path:line: [rule] message``).

Allowlist entries shrink as the v0.3.0 refactor lands:
  - R1 allow ``routers/assessments.py``  -> removed by T5 (BackgroundTasks)
  - R2 allow ``routers/assessments.py``  -> removed by T3 (UnitOfWork) ✔ done
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LineRule:
    rule_id: str
    pattern: str
    scope: tuple[str, ...]  # relative-path prefixes the rule applies to ("" = all)
    allow: frozenset[str]   # relative paths exempt (transitional, see module doc)
    message: str


LINE_RULES: tuple[LineRule, ...] = (
    LineRule(
        rule_id="R1",
        pattern=r"threading\.Thread\(",
        scope=("interfaces/api/routers/",),
        allow=frozenset({"interfaces/api/routers/assessments.py"}),  # T5 removes
        message="raw threading.Thread in a router (use BackgroundTasks; v3 race class)",
    ),
    LineRule(
        rule_id="R2",
        pattern=r"\.open_session\(\)",
        scope=("",),
        allow=frozenset({
            "infrastructure/db/session.py",  # session / UnitOfWork owner
            "infrastructure/audit/database_recorder.py",  # session-per-call recorder
            "infrastructure/repositories/sqlalchemy_audit_chain.py",
            "interfaces/api/main.py",  # SSE snapshot polls (short-lived)
        }),
        message=".open_session() outside sanctioned modules (v4 hot-path connection class)",
    ),
)

# Files where EVERY ``.record(...)`` call must carry ``session=`` (v5 class).
SESSION_REQUIRED_RECORD_FILES: frozenset[str] = frozenset({
    "application/canary.py",
    "application/oracle_service.py",
    "infrastructure/egress/nft_scope.py",
    "infrastructure/oracle/rescan_verifier.py",
})
# execution.py: only ``audit_chain.record`` must thread session=. The
# AuditService.record call there is bound to the correct session through its
# repo and ignores the parameter by design.
AUDIT_CHAIN_RECORD_FILE = "application/execution.py"


def _iter_python_files(root: Path) -> list[tuple[str, Path]]:
    return [
        (path.relative_to(root).as_posix(), path)
        for path in sorted(root.rglob("*.py"))
    ]


def _check_line_rules(root: Path, violations: list[str]) -> None:
    for rel, path in _iter_python_files(root):
        rules = [
            rule for rule in LINE_RULES
            if any(rel.startswith(scope) for scope in rule.scope)
            and rel not in rule.allow
        ]
        if not rules:
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for rule in rules:
            for lineno, line in enumerate(lines, 1):
                if line.lstrip().startswith("#"):
                    continue  # comments may mention a pattern without using it
                if re.search(rule.pattern, line):
                    violations.append(
                        f"{rel}:{lineno}: [{rule.rule_id}] {rule.message}: "
                        f"{line.strip()}"
                    )


def _record_calls_missing_session(path: Path, *, only_audit_chain: bool) -> list[int]:
    """Line numbers of ``.record(...)`` calls lacking a ``session=`` keyword."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    missing: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "record":
            continue
        if only_audit_chain:
            value = func.value
            if not (isinstance(value, ast.Name) and value.id == "audit_chain"):
                continue
        if not any(keyword.arg == "session" for keyword in node.keywords):
            missing.append(node.lineno)
    return missing


def _check_record_rules(root: Path, violations: list[str]) -> None:
    for rel, path in _iter_python_files(root):
        if rel in SESSION_REQUIRED_RECORD_FILES:
            for lineno in _record_calls_missing_session(path, only_audit_chain=False):
                violations.append(
                    f"{rel}:{lineno}: [R3] audit .record() without session= "
                    f"(opens its own connection; v4/v5 class)"
                )
        elif rel == AUDIT_CHAIN_RECORD_FILE:
            for lineno in _record_calls_missing_session(path, only_audit_chain=True):
                violations.append(
                    f"{rel}:{lineno}: [R3b] audit_chain.record() without session="
                )


def main(argv: list[str] | None = None) -> int:
    default_root = Path(__file__).resolve().parents[1] / "src" / "secopent"
    parser = argparse.ArgumentParser(
        description="Forbidden-pattern linter for the v3/v4/v5 bug class."
    )
    parser.add_argument(
        "--root", type=Path, default=default_root,
        help="src/secopent-shaped tree to scan (default: the real source tree)",
    )
    args = parser.parse_args(argv)
    root: Path = args.root
    if not root.is_dir():
        print(f"root not found: {root}", file=sys.stderr)
        return 2

    violations: list[str] = []
    _check_line_rules(root, violations)
    _check_record_rules(root, violations)
    if violations:
        print("\n".join(violations))
        print(f"\nforbidden-pattern linter: {len(violations)} violation(s)")
        return 1
    print("forbidden-pattern linter: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
