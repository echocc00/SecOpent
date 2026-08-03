# tests/infrastructure/test_strix_report.py
"""Strix vulnerabilities.json parser (P2 Task 1) - fixture-driven."""
from __future__ import annotations

from pathlib import Path

import pytest

from secopent.infrastructure.peer_agents.strix_report import (
    StrixReportParseError,
    normalize_cwe,
    parse_vulnerabilities_json,
)

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "peer_reports" / "strix_vulnerabilities.json"
)


class TestNormalizeCwe:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("CWE-89", "CWE-89"),
            ("cwe: 918", "CWE-918"),
            ("306", "CWE-306"),
            ("", ""),
        ],
    )
    def test_variants(self, raw: str, expected: str) -> None:
        assert normalize_cwe(raw) == expected


class TestParser:
    def test_parses_fixture_into_findings(self) -> None:
        findings = parse_vulnerabilities_json(
            FIXTURE.read_text(encoding="utf-8"), run_id="run-x", agent="strix",
        )
        assert len(findings) == 3
        first = findings[0]
        assert first.run_id == "run-x"
        assert first.agent_name == "strix"
        assert first.asset.startswith("http://")
        assert "CWE-89" in first.cwe
        assert first.severity_hint == "high"
        assert first.payload_summary  # poc_description summary

    def test_missing_target_rejected_as_parse_error_entry(self) -> None:
        # Entries without a target are dropped and counted as problems; the
        # rest of the report is not discarded.
        findings, problems = parse_vulnerabilities_json(
            '[{"title": "no target", "severity": "high"}]',
            run_id="r", agent="strix", with_problems=True,
        )
        assert findings == ()
        assert problems == 1

    def test_corrupt_json_raises(self) -> None:
        with pytest.raises(StrixReportParseError):
            parse_vulnerabilities_json("{not json", run_id="r", agent="strix")
