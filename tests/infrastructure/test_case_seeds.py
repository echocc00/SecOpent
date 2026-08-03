# tests/infrastructure/test_case_seeds.py
"""Case DSL seed parsing: validates P1a seed YAMLs parse correctly (P1a Task 4)."""
from __future__ import annotations

from pathlib import Path

import yaml

from secopent.domain.cases.models import CaseOrigin, CaseStatus
from secopent.domain.cases.yaml_schema import case_from_mapping

_SEED_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "cases" / "seed"


def _load_seed(name: str) -> dict:
    raw = (_SEED_DIR / name).read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    assert isinstance(data, dict), f"{name}: top-level must be a mapping"
    return data


class TestCaseSeeds:
    """Each seed YAML must parse via case_from_mapping and satisfy invariants."""

    def test_idor_horizontal_parses(self) -> None:
        case = case_from_mapping(_load_seed("idor-horizontal.yaml"))
        assert case.origin == CaseOrigin.MANUAL
        assert case.status == CaseStatus.DRAFT
        assert case.verification is not None
        assert case.verification.reproduce >= 1
        assert len(case.cwe) > 0

    def test_jwt_alg_confusion_parses(self) -> None:
        case = case_from_mapping(_load_seed("jwt-alg-confusion.yaml"))
        assert case.origin == CaseOrigin.MANUAL
        assert case.status == CaseStatus.DRAFT
        assert case.verification is not None
        assert case.verification.reproduce >= 1
        assert len(case.cwe) > 0

    def test_path_traversal_read_parses(self) -> None:
        case = case_from_mapping(_load_seed("path-traversal-read.yaml"))
        assert case.origin == CaseOrigin.MANUAL
        assert case.status == CaseStatus.DRAFT
        assert case.verification is not None
        assert case.verification.reproduce >= 1
        assert len(case.cwe) > 0

    def test_race_double_spend_parses(self) -> None:
        case = case_from_mapping(_load_seed("race-double-spend.yaml"))
        assert case.origin == CaseOrigin.MANUAL
        assert case.status == CaseStatus.DRAFT
        assert case.verification is not None
        assert case.verification.reproduce >= 1
        assert len(case.cwe) > 0
