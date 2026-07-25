# src/secopent/infrastructure/repositories/sqlalchemy_assets.py
"""SqlAlchemy repository for the asset graph (relation table, §6)."""
from __future__ import annotations

from sqlalchemy.orm import Session

from ...domain.assets.graph import AssetGraph
from ...domain.assets.models import AssetEdge, AssetNode, AssetRelation, AssetType
from ..db.asset_models import CoreAssetEdge, CoreAssetNode


def _node_id(node: AssetNode) -> str:
    return f"{node.type.value}:{node.value}"


def _edge_id(edge: AssetEdge) -> str:
    return f"{_node_id(edge.src)}|{edge.rel.value}|{_node_id(edge.dst)}"


class SqlAlchemyAssetRepository:
    """Persist and load an AssetGraph as nodes + edges rows."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def save_graph(self, graph: AssetGraph) -> None:
        for node in graph.nodes:
            self._session.merge(
                CoreAssetNode(
                    id=_node_id(node), asset_type=node.type.value, value=node.value
                )
            )
        for edge in graph.edges:
            self._session.merge(
                CoreAssetEdge(
                    id=_edge_id(edge),
                    src_id=_node_id(edge.src),
                    dst_id=_node_id(edge.dst),
                    rel=edge.rel.value,
                )
            )

    def load_graph(self) -> AssetGraph:
        nodes: dict[str, AssetNode] = {}
        for row in self._session.query(CoreAssetNode).all():
            node = AssetNode(type=AssetType(row.asset_type), value=row.value)
            nodes[row.id] = node
        graph = AssetGraph()
        for node in nodes.values():
            graph = graph.add_node(node)
        for row in self._session.query(CoreAssetEdge).all():
            graph = graph.add_edge(
                AssetEdge(
                    src=nodes[row.src_id],
                    dst=nodes[row.dst_id],
                    rel=AssetRelation(row.rel),
                )
            )
        return graph
