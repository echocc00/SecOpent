# src/secopent/interfaces/api/routers/assets.py
"""Assets resource router (Phase A P1, W1): the discovery graph.

Read-only surface over ``SqlAlchemyAssetRepository`` - returns the whole asset
graph (nodes + directed edges) so the Web UI can render the Domain -> IP ->
Port -> Service -> URL -> Endpoint -> Technology relation table.
"""
from __future__ import annotations

from fastapi import APIRouter

from ....domain.assets.graph import AssetGraph
from ....infrastructure.repositories.sqlalchemy_assets import SqlAlchemyAssetRepository
from ..deps import DbSession
from ..schemas import AssetEdgeOut, AssetGraphOut, AssetNodeOut

router = APIRouter(prefix="/assets", tags=["assets"])


def _to_out(graph: AssetGraph) -> AssetGraphOut:
    return AssetGraphOut(
        nodes=[AssetNodeOut(type=n.type.value, value=n.value) for n in graph.nodes],
        edges=[
            AssetEdgeOut(
                src=AssetNodeOut(type=e.src.type.value, value=e.src.value),
                dst=AssetNodeOut(type=e.dst.type.value, value=e.dst.value),
                rel=e.rel.value,
            )
            for e in graph.edges
        ],
    )


@router.get("", response_model=AssetGraphOut)
def get_asset_graph(session: DbSession) -> AssetGraphOut:
    return _to_out(SqlAlchemyAssetRepository(session).load_graph())
