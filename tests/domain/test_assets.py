"""TDD tests for the AssetGraph domain (M4 Task 1, §6 relation-table graph).

The asset graph maps discovered assets and their relationships
(Domain -> IP -> Port -> Service -> URL -> Endpoint -> Technology) as a plain
relation table (nodes + edges), not a graph database. Nodes/edges are immutable;
``add_*`` return new graphs.
"""
from __future__ import annotations

import pytest

from secopent.domain.assets.graph import AssetGraph
from secopent.domain.assets.models import (
    AssetEdge,
    AssetNode,
    AssetRelation,
    AssetType,
)
from secopent.domain.common.errors import DomainValidationError


def test_asset_type_has_seven_kinds() -> None:
    assert {t.value for t in AssetType} == {
        "domain",
        "ip",
        "port",
        "service",
        "url",
        "endpoint",
        "technology",
    }


def test_asset_relation_has_six_kinds() -> None:
    assert {r.value for r in AssetRelation} == {
        "resolves_to",
        "exposes",
        "runs",
        "serves",
        "contains",
        "uses",
    }


def test_node_requires_value() -> None:
    with pytest.raises(DomainValidationError):
        AssetNode(type=AssetType.DOMAIN, value="")


def test_add_node_dedups() -> None:
    node = AssetNode(type=AssetType.DOMAIN, value="example.com")
    graph = AssetGraph().add_node(node).add_node(node)
    assert graph.nodes == (node,)


def test_add_edge_auto_includes_endpoints() -> None:
    domain = AssetNode(type=AssetType.DOMAIN, value="example.com")
    ip = AssetNode(type=AssetType.IP, value="192.0.2.1")
    edge = AssetEdge(src=domain, dst=ip, rel=AssetRelation.RESOLVES_TO)
    graph = AssetGraph().add_edge(edge)
    assert set(graph.nodes) == {domain, ip}
    assert graph.edges == (edge,)


def test_neighbors_returns_outgoing_targets() -> None:
    domain = AssetNode(type=AssetType.DOMAIN, value="example.com")
    ip = AssetNode(type=AssetType.IP, value="192.0.2.1")
    graph = AssetGraph().add_edge(
        AssetEdge(src=domain, dst=ip, rel=AssetRelation.RESOLVES_TO)
    )
    assert graph.neighbors(domain) == (ip,)


def test_neighbors_filtered_by_relation() -> None:
    domain = AssetNode(type=AssetType.DOMAIN, value="example.com")
    ip = AssetNode(type=AssetType.IP, value="192.0.2.1")
    url = AssetNode(type=AssetType.URL, value="https://example.com/")
    graph = (
        AssetGraph()
        .add_edge(AssetEdge(src=domain, dst=ip, rel=AssetRelation.RESOLVES_TO))
        .add_edge(AssetEdge(src=domain, dst=url, rel=AssetRelation.SERVES))
    )
    assert graph.neighbors(domain, rel=AssetRelation.RESOLVES_TO) == (ip,)
    assert graph.neighbors(domain, rel=AssetRelation.SERVES) == (url,)


def test_find_by_type_and_value() -> None:
    domain = AssetNode(type=AssetType.DOMAIN, value="example.com")
    ip = AssetNode(type=AssetType.IP, value="192.0.2.1")
    graph = AssetGraph().add_node(domain).add_node(ip)
    assert graph.find(node_type=AssetType.IP) == (ip,)
    assert graph.find(value="example.com") == (domain,)


def test_graph_is_immutable() -> None:
    empty = AssetGraph()
    node = AssetNode(type=AssetType.DOMAIN, value="example.com")
    grown = empty.add_node(node)
    assert empty.nodes == ()  # original unchanged
    assert grown.nodes == (node,)
