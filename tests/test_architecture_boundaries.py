# tests/test_architecture_boundaries.py
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "secopent"
FORBIDDEN = {"fastapi", "sqlalchemy", "httpx", "docker", "mcp", "cryptography"}


def test_domain_does_not_import_frameworks() -> None:
    domain = ROOT / "domain"
    assert domain.is_dir(), "domain package is missing"
    violations: list[str] = []
    for path in domain.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [item.name.split(".")[0] for item in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            for name in names:
                if name in FORBIDDEN:
                    violations.append(f"{path.relative_to(ROOT)} imports {name}")
    assert violations == [], "domain must not import frameworks: " + ", ".join(violations)


def test_application_does_not_import_frameworks() -> None:
    app = ROOT / "application"
    assert app.is_dir(), "application package is missing"
    violations: list[str] = []
    for path in app.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [item.name.split(".")[0] for item in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            for name in names:
                if name in FORBIDDEN:
                    violations.append(f"{path.relative_to(ROOT)} imports {name}")
    assert violations == [], "application must not import frameworks: " + ", ".join(violations)
