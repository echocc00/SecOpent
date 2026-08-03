# tests/security/test_no_agpl_code.py
"""AGPL code-absence guard (P3 Task 5).

Asserts that no file under src/ contains Keygraph Shannon copyright text.
This is the automated enforcement of ADR decision D2 (process isolation):
SecOpent must never import, copy, or link Shannon AGPL-3.0 source code.
"""
from __future__ import annotations

from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[2] / "src"
FORBIDDEN_MARKER = "Copyright (C) 2025 Keygraph"


def _text_files(root: Path) -> list[Path]:
    """All text-decodable files under root (skip binaries and caches)."""
    result: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if "__pycache__" in str(path):
            continue
        if path.suffix in {".pyc", ".pyo", ".so", ".dll", ".exe", ".whl"}:
            continue
        result.append(path)
    return result


def test_no_keygraph_copyright_in_src() -> None:
    """No file under src/ may contain the Keygraph copyright marker."""
    violations: list[str] = []
    for path in _text_files(SRC_ROOT):
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue
        if FORBIDDEN_MARKER in content:
            violations.append(str(path.relative_to(SRC_ROOT)))
    assert violations == [], (
        f"AGPL code leak detected! Files containing '{FORBIDDEN_MARKER}': "
        + ", ".join(violations)
    )
