# src/secopent/domain/cases/yaml_schema.py
"""Pure ``dict -> CaseDefinition`` schema validation for YAML cases (§11.2).

The case engine (infrastructure) turns a YAML *string* into a plain mapping
(via ``yaml.safe_load``); this module turns that mapping into a validated
``CaseDefinition``. Keeping the schema logic here - operating only on stdlib
mappings - keeps the domain framework-free.

The schema is Nuclei-compatible (id / classification / steps) plus three
SecOpent extension hooks: the ``{{canary_token}}`` placeholder, the
``verification`` block, and the ``classification`` block that feeds
CoverageMatrix.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ..common.errors import DomainValidationError
from ..policy.models import RiskClass
from .models import (
    CaseAssertion,
    CaseDefinition,
    CaseOrigin,
    CaseStep,
    CaseVerification,
)

# Placeholder a probe substitutes the oracle's canary token into (§11.2).
CANARY_PLACEHOLDER = "{{canary_token}}"


def _require_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DomainValidationError(f"case field {field} must be a mapping")
    return value


def _str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DomainValidationError(f"case field {field} must be a non-empty string")
    return value


def _opt_str(value: Any, default: str) -> str:
    if value is None:
        return default
    if isinstance(value, str) and value.strip():
        return value
    return default


def _str_tuple(value: Any, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence):
        return tuple(str(item) for item in value)
    raise DomainValidationError(f"case field {field} must be a string list")


def _parse_risk(value: Any) -> RiskClass:
    try:
        return RiskClass(_str(value, "risk"))
    except ValueError as exc:
        raise DomainValidationError(f"unknown case risk: {value!r}") from exc


def _parse_origin(value: Any) -> CaseOrigin:
    if value is None:
        return CaseOrigin.MANUAL
    try:
        return CaseOrigin(_opt_str(value, CaseOrigin.MANUAL.value))
    except ValueError as exc:
        raise DomainValidationError(f"unknown case origin: {value!r}") from exc


def _parse_steps(value: Any) -> tuple[CaseStep, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence):
        raise DomainValidationError("case field steps must be a list")
    steps: list[CaseStep] = []
    for idx, raw in enumerate(value):
        step_map = _require_mapping(raw, f"steps[{idx}]")
        spec_raw = step_map.get("spec", {})
        spec = dict(spec_raw) if isinstance(spec_raw, Mapping) else {}
        steps.append(
            CaseStep(
                id=_str(step_map.get("id"), f"steps[{idx}].id"),
                action=_str(step_map.get("action"), f"steps[{idx}].action"),
                spec=spec,
            )
        )
    return tuple(steps)


def _parse_assertions(value: Any) -> tuple[CaseAssertion, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence):
        raise DomainValidationError("case field assertions must be a list")
    assertions: list[CaseAssertion] = []
    for idx, raw in enumerate(value):
        assertion_map = _require_mapping(raw, f"assertions[{idx}]")
        assertions.append(
            CaseAssertion(
                id=_str(assertion_map.get("id"), f"assertions[{idx}].id"),
                expression=_str(
                    assertion_map.get("expression"), f"assertions[{idx}].expression"
                ),
            )
        )
    return tuple(assertions)


def _parse_verification(value: Any) -> CaseVerification | None:
    if value is None:
        return None
    verif_map = _require_mapping(value, "verification")
    reproduce_raw = verif_map.get("reproduce", 1)
    if not isinstance(reproduce_raw, int) or isinstance(reproduce_raw, bool):
        raise DomainValidationError("verification.reproduce must be an integer")
    return CaseVerification(
        method=_str(verif_map.get("method"), "verification.method"),
        reproduce=reproduce_raw,
    )


def case_from_mapping(data: Mapping[str, Any]) -> CaseDefinition:
    """Build a validated CaseDefinition from a parsed case mapping.

    Raises DomainValidationError on any missing/invalid required field. The
    CaseDefinition constructor performs the final structural validation.
    """
    _require_mapping(data, "case")
    classification_raw = data.get("classification")
    classification: Mapping[str, Any] = (
        classification_raw if isinstance(classification_raw, Mapping) else {}
    )
    return CaseDefinition(
        id=_str(data.get("id"), "id"),
        version=_str(data.get("version"), "version"),
        author=_str(data.get("author"), "author"),
        risk=_parse_risk(data.get("risk")),
        target_type=_str(data.get("target_type"), "target_type"),
        schema=_opt_str(data.get("schema"), "nuclei+secopent/1"),
        steps=_parse_steps(data.get("steps")),
        preconditions=_str_tuple(data.get("preconditions"), "preconditions"),
        assertions=_parse_assertions(data.get("assertions")),
        evidence_req=_str_tuple(data.get("evidence_req"), "evidence_req"),
        cwe=_str_tuple(classification.get("cwe") or data.get("cwe"), "cwe"),
        cve=_str_tuple(classification.get("cve") or data.get("cve"), "cve"),
        owasp=_str_tuple(classification.get("owasp") or data.get("owasp"), "owasp"),
        verification=_parse_verification(data.get("verification")),
        signature=_opt_str(data.get("signature"), ""),
        min_engine_version=_opt_str(data.get("min_engine_version"), "1.0.0"),
        origin=_parse_origin(data.get("origin")),
    )


def _contains_canary(value: Any) -> bool:
    """Recursively detect the canary placeholder in a spec value."""
    if isinstance(value, str):
        return CANARY_PLACEHOLDER in value
    if isinstance(value, Mapping):
        return any(_contains_canary(v) for v in value.values())
    if isinstance(value, Sequence):
        return any(_contains_canary(v) for v in value)
    return False


def uses_canary_token(case: CaseDefinition) -> bool:
    """Whether any step spec embeds the ``{{canary_token}}`` placeholder."""
    return any(_contains_canary(step.spec) for step in case.steps)
