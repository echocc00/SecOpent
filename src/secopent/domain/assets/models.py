# src/secopent/domain/assets/models.py
"""Asset graph domain models (§6): nodes + edges as a relation table.

Discovered assets form a graph Domain -> IP -> Port -> Service -> URL ->
Endpoint -> Technology. It is expressed as a plain relation table (immutable
nodes + edges), not a graph database, so it persists trivially in SQL and stays
framework-free.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..common.errors import DomainValidationError


class AssetType(StrEnum):
    """The asset kinds tracked in the graph."""

    DOMAIN = "domain"
    IP = "ip"
    PORT = "port"
    SERVICE = "service"
    URL = "url"
    ENDPOINT = "endpoint"
    TECHNOLOGY = "technology"


class AssetRelation(StrEnum):
    """How two assets relate (edge labels)."""

    RESOLVES_TO = "resolves_to"  # domain -> ip
    EXPOSES = "exposes"  # ip -> port
    RUNS = "runs"  # port -> service
    SERVES = "serves"  # service/domain -> url
    CONTAINS = "contains"  # url -> endpoint
    USES = "uses"  # endpoint/service -> technology


@dataclass(frozen=True, slots=True)
class AssetNode:
    """A discovered asset (a typed value)."""

    type: AssetType
    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise DomainValidationError("AssetNode.value must be non-empty")


@dataclass(frozen=True, slots=True)
class AssetEdge:
    """A directed relationship src -rel-> dst between two assets."""

    src: AssetNode
    dst: AssetNode
    rel: AssetRelation
