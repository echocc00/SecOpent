# src/secopent/infrastructure/catalog/handbook_registry.py
"""HandbookRegistry: curated structured attack handbooks (spec §6 P1a).

Handbooks are the deterministic distillation of attack-knowledge sources
(first batch derived from usestrix/strix skills, Apache-2.0, attribution in
NOTICE). Shape: attack_surface / recon_endpoints / payload_classes /
verification_hint - consumed by planner context and case authoring, NEVER
executed directly (the case engine executes cases, the oracle verifies).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ...domain.common.errors import DomainError

_REQUIRED_FIELDS = (
    "id", "title", "cwe", "owasp", "provenance",
    "attack_surface", "payload_classes", "verification_hint",
)
_PROVENANCE_FIELDS = ("derived_from", "license")


class HandbookSchemaError(DomainError):
    """A handbook file violates the curation schema."""


@dataclass(frozen=True, slots=True)
class Handbook:
    id: str
    title: str
    cwe: tuple[str, ...]
    owasp: tuple[str, ...]
    provenance_source: str
    provenance_license: str
    attack_surface: tuple[str, ...]
    recon_endpoints: tuple[str, ...]
    payload_classes: tuple[str, ...]
    verification_hint: str


def _parse(data: dict[str, Any], path: Path) -> Handbook:
    for field_name in _REQUIRED_FIELDS:
        if field_name not in data or data[field_name] in (None, "", []):
            raise HandbookSchemaError(f"{path}: missing field '{field_name}'")
    provenance = data["provenance"]
    if not isinstance(provenance, dict):
        raise HandbookSchemaError(f"{path}: provenance must be a mapping")
    for field_name in _PROVENANCE_FIELDS:
        if field_name not in provenance:
            raise HandbookSchemaError(
                f"{path}: provenance missing '{field_name}'"
            )
    return Handbook(
        id=str(data["id"]),
        title=str(data["title"]),
        cwe=tuple(str(c) for c in data["cwe"]),
        owasp=tuple(str(o) for o in data["owasp"]),
        provenance_source=str(provenance["derived_from"]),
        provenance_license=str(provenance["license"]),
        attack_surface=tuple(str(s) for s in data["attack_surface"]),
        recon_endpoints=tuple(str(e) for e in data.get("recon_endpoints", [])),
        payload_classes=tuple(
            str(p["name"]) if isinstance(p, dict) else str(p)
            for p in data["payload_classes"]
        ),
        verification_hint=str(data["verification_hint"]),
    )


class HandbookRegistry:
    """All curated handbooks, keyed by id."""

    def __init__(self, handbooks: tuple[Handbook, ...]) -> None:
        self._by_id = {h.id: h for h in handbooks}

    @classmethod
    def load(cls, directory: Path) -> HandbookRegistry:
        handbooks: list[Handbook] = []
        for path in sorted(Path(directory).glob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise HandbookSchemaError(f"{path}: top level must be a mapping")
            handbooks.append(_parse(data, path))
        return cls(tuple(handbooks))

    def get(self, handbook_id: str) -> Handbook | None:
        return self._by_id.get(handbook_id)

    def all(self) -> tuple[Handbook, ...]:
        return tuple(self._by_id.values())


def load_default_handbooks() -> HandbookRegistry:
    """Load the packaged handbook set (ships with the product)."""
    return HandbookRegistry.load(Path(__file__).parent / "handbooks")
