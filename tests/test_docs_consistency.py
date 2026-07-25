from __future__ import annotations

from pathlib import Path


def test_readme_points_to_catalog_driven_design() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    assert "catalog-driven-agent-workbench-design.md" in readme
    assert "M0" in readme


def test_core_boundaries_doc_exists() -> None:
    assert Path("docs/architecture/core-boundaries.md").is_file()


def test_knowledge_layer_doc_exists() -> None:
    path = Path("docs/architecture/knowledge-layer.md")
    assert path.is_file()
    content = path.read_text(encoding="utf-8")
    # The four-sublayer structure and the regression gate must be documented.
    assert "TestCatalog" in content
    assert "CoverageMatrix" in content
    assert "退化门禁" in content


def test_adapters_doc_exists() -> None:
    path = Path("docs/adapters/README.md")
    assert path.is_file()
    content = path.read_text(encoding="utf-8")
    # The four coverage domains and the manifest contract must be documented.
    for domain in ("asset", "web", "network", "cloud"):
        assert domain in content
    assert "AdapterManifest" in content


def test_readme_mentions_m1_complete() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    assert "M1" in readme
    assert "knowledge-layer.md" in readme
    assert "docs/adapters/README.md" in readme


def test_verification_doc_exists() -> None:
    path = Path("docs/architecture/verification.md")
    assert path.is_file()
    content = path.read_text(encoding="utf-8")
    # N/N oracle, canary, and the LLM boundary must be documented.
    assert "N/N" in content
    assert "Canary" in content or "canary" in content
    assert "VerificationMethodRegistry" in content


def test_yaml_dsl_doc_exists() -> None:
    path = Path("docs/cases/yaml-dsl.md")
    assert path.is_file()
    content = path.read_text(encoding="utf-8")
    # Nuclei-compatible base, no-eval AST, and the risk gate must be documented.
    assert "Nuclei" in content
    assert "eval" in content
    assert "RiskAnalyzer" in content


def test_readme_mentions_m2() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    assert "M2" in readme
    assert "verification.md" in readme
    assert "docs/cases/yaml-dsl.md" in readme
