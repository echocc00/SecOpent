# src/secopent/infrastructure/case_engine/yaml_parser.py
"""YAML string -> CaseDefinition (§11.2 Nuclei-compatible + extensions).

Uses ``yaml.safe_load`` (never ``yaml.load``) so a case file cannot instantiate
arbitrary Python objects, then delegates structure validation to the domain
``case_from_mapping``. Parse/structure failures surface as ``CaseParseError``.
"""
from __future__ import annotations

import yaml

from secopent.domain.cases.models import CaseDefinition
from secopent.domain.cases.yaml_schema import case_from_mapping
from secopent.domain.common.errors import DomainError, DomainValidationError


class CaseParseError(DomainError):
    """Raised when a case YAML string cannot be parsed into a CaseDefinition."""


def load_case_yaml(yaml_str: str) -> CaseDefinition:
    """Parse a case YAML string into a validated CaseDefinition."""
    try:
        data = yaml.safe_load(yaml_str)
    except yaml.YAMLError as exc:
        raise CaseParseError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise CaseParseError("case YAML must be a mapping at the top level")
    try:
        return case_from_mapping(data)
    except DomainValidationError as exc:
        raise CaseParseError(f"invalid case definition: {exc}") from exc
