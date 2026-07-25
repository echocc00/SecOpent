# src/secopent/domain/assets/graph.py
"""AssetGraph: an immutable relation-table graph of discovered assets (§6).

Nodes and edges are immutable; ``add_node`` / ``add_edge`` return a new graph
(the original is unchanged). ``add_edge`` auto-includes its endpoint nodes so a
graph can be built incrementally from observations. Queries answer "what is
related to this asset" (optionally filtered by relation) and "find assets by
type/value".
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from .models import AssetEdge, AssetNode, AssetRelation, AssetType


@dataclass(frozen=True, slots=True)
class AssetGraph:
    """A relation-table asset graph (nodes + directed edges)."""

    nodes: tuple[AssetNode, ...] = ()
    edges: tuple[AssetEdge, ...] = ()

    def has_node(self, node: AssetNode) -> bool:
        return node in self.nodes

    def add_node(self, node: AssetNode) -> AssetGraph:
        """Return a new graph with the node added (de-duplicated)."""
        if node in self.nodes:
            return self
        return replace(self, nodes=(*self.nodes, node))

    def add_edge(self, edge: AssetEdge) -> AssetGraph:
        """Return a new graph with the edge added; endpoints auto-included."""
        graph = self
        if edge.src not in graph.nodes:
            graph = replace(graph, nodes=(*graph.nodes, edge.src))
        if edge.dst not in graph.nodes:
            graph = replace(graph, nodes=(*graph.nodes, edge.dst))
        if edge in graph.edges:
            return graph
        return replace(graph, edges=(*graph.edges, edge))

    def neighbors(
        self, node: AssetNode, rel: AssetRelation | None = None
    ) -> tuple[AssetNode, ...]:
        """Outgoing targets of ``node`` (optionally filtered by relation)."""
        return tuple(
            edge.dst
            for edge in self.edges
            if edge.src == node and (rel is None or edge.rel is rel)
        )

    def find(
        self,
        node_type: AssetType | None = None,
        value: str | None = None,
    ) -> tuple[AssetNode, ...]:
        """Find nodes by type and/or value (both None -> all nodes)."""
        return tuple(
            node
            for node in self.nodes
            if (node_type is None or node.type is node_type)
            and (value is None or node.value == value)
        )
