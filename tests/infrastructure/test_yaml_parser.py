"""TDD tests for the case YAML parser (M2 Task 7, §11.2 Nuclei-compatible+ext).

The parser turns a YAML *string* into a validated CaseDefinition via
``yaml.safe_load`` + the domain ``case_from_mapping``. It uses safe_load (never
``yaml.load``) so a case file cannot instantiate arbitrary Python objects.
"""
from __future__ import annotations

import pytest

from secopent.domain.cases.models import CaseDefinition, CaseOrigin
from secopent.domain.policy.models import RiskClass
from secopent.infrastructure.case_engine.yaml_parser import (
    CaseParseError,
    load_case_yaml,
)

_VALID_YAML = """
id: sqli-time-based
version: "1.0.0"
author: analyst
schema: nuclei+secopent/1
risk: active
target_type: http
origin: manual
classification:
  cwe: [CWE-89]
  owasp: [A03:2021]
verification:
  method: sqli
  reproduce: 5
steps:
  - id: req1
    action: http.request
    spec:
      method: GET
      path: "/?id={{canary_token}}"
assertions:
  - id: a1
    expression: "contains(body, canary_token)"
"""


def test_load_valid_case() -> None:
    case = load_case_yaml(_VALID_YAML)
    assert isinstance(case, CaseDefinition)
    assert case.id == "sqli-time-based"
    assert case.risk is RiskClass.ACTIVE
    assert case.origin is CaseOrigin.MANUAL
    assert case.cwe == ("CWE-89",)
    assert case.verification is not None
    assert case.verification.method == "sqli"
    assert case.steps[0].spec["path"] == "/?id={{canary_token}}"
    assert case.assertions[0].expression == "contains(body, canary_token)"


def test_load_rejects_invalid_yaml_syntax() -> None:
    with pytest.raises(CaseParseError):
        load_case_yaml("id: [unclosed\n  bad: : :")


def test_load_rejects_non_mapping_yaml() -> None:
    with pytest.raises(CaseParseError):
        load_case_yaml("- just\n- a\n- list\n")


def test_load_rejects_missing_required_field() -> None:
    with pytest.raises(CaseParseError):
        load_case_yaml("version: '1.0'\nauthor: a\n")  # no id / steps


def test_load_uses_safe_load_no_python_objects() -> None:
    # A YAML python/object tag must NOT be deserialized into a Python object.
    # safe_load raises on unknown tags -> CaseParseError.
    with pytest.raises(CaseParseError):
        load_case_yaml("id: !!python/object/apply:os.system ['id']\n")
