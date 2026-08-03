# tests/infrastructure/test_shannon_deliverables.py
"""Shannon deliverables parser (P3 Task 1) - permissive markdown parsing."""
from __future__ import annotations

from pathlib import Path

from secopent.infrastructure.peer_agents.shannon_deliverables import (
    parse_deliverable_markdown,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "peer_reports"


class TestAnalysisDeliverable:
    def test_extracts_findings_with_severity_and_target(self) -> None:
        content = (FIXTURES / "shannon_injection_deliverable.md").read_text(encoding="utf-8")
        findings, problems = parse_deliverable_markdown(
            content, run_id="run-s1", agent="shannon", vuln_class="injection",
        )
        assert len(findings) == 2
        assert findings[0].severity_hint.lower() == "high"
        assert findings[0].asset  # 目标 URL/host 非空
        assert "CWE-89" in findings[0].cwe
        assert problems == 0

    def test_finding_without_cwe_kept_with_empty_cwe(self) -> None:
        content = (FIXTURES / "shannon_injection_deliverable.md").read_text(encoding="utf-8")
        findings, _ = parse_deliverable_markdown(
            content, run_id="run-s1", agent="shannon", vuln_class="injection",
        )
        assert any(f.cwe == () for f in findings)


class TestExploitDeliverable:
    def test_exploit_record_maps_target_from_poc(self) -> None:
        content = (FIXTURES / "shannon_exploit_deliverable.md").read_text(encoding="utf-8")
        findings, problems = parse_deliverable_markdown(
            content, run_id="run-s1", agent="shannon", vuln_class="exploit",
        )
        assert len(findings) == 1
        assert findings[0].asset.startswith("http")
        assert findings[0].payload_summary  # PoC 摘要


class TestPermissiveness:
    def test_empty_document_yields_zero_findings_not_error(self) -> None:
        findings, problems = parse_deliverable_markdown(
            "", run_id="r", agent="shannon", vuln_class="injection",
        )
        assert findings == () and problems == 0

    def test_unstructured_text_counts_as_problem(self) -> None:
        findings, problems = parse_deliverable_markdown(
            "just prose without any findings section",
            run_id="r", agent="shannon", vuln_class="injection",
        )
        assert findings == () and problems == 1
