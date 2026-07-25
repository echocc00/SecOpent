from __future__ import annotations

from pathlib import Path


def test_readme_points_to_catalog_driven_design() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    assert "catalog-driven-agent-workbench-design.md" in readme
    assert "M0" in readme


def test_core_boundaries_doc_exists() -> None:
    assert Path("docs/architecture/core-boundaries.md").is_file()
