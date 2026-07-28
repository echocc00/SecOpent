# src/secopent/interfaces/api/routers/catalog.py
"""Catalog resource router (Phase A P1, W10 support): the curated TestCatalog.

The Planner needs a TestCatalog to generate an execution plan for an
assessment's asset types. This router lets the knowledge layer be seeded /
imported (a baseline catalog ships with curation in P3; until then an operator
or the E2E suite seeds one here).

- ``POST /catalog`` - register a catalog version (asset type -> required classes);
- ``GET /catalog/latest`` - the highest-versioned catalog;
- ``GET /catalog/{version}`` - a specific version.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ....domain.catalog.models import AssetType, RequiredTestClass, TestCatalog
from ....domain.policy.models import RiskClass
from ....infrastructure.repositories.sqlalchemy_catalog import (
    SqlAlchemyCatalogRepository,
)
from ..deps import DbSession
from ..schemas import CatalogCreate, CatalogOut, RequiredTestClassIn

router = APIRouter(prefix="/catalog", tags=["catalog"])


def _to_out(catalog: TestCatalog) -> CatalogOut:
    return CatalogOut(
        version=catalog.version,
        digest=catalog.digest,
        mappings={
            asset_type.value: [
                RequiredTestClassIn(
                    id=cls.id,
                    cwe=list(cls.cwe),
                    owasp=list(cls.owasp),
                    risk=cls.risk.value,
                )
                for cls in classes
            ]
            for asset_type, classes in catalog.mappings.items()
        },
    )


@router.post("", status_code=201, response_model=CatalogOut)
def create_catalog(payload: CatalogCreate, session: DbSession) -> CatalogOut:
    try:
        mappings = {
            AssetType(asset_type): tuple(
                RequiredTestClass(
                    id=cls.id,
                    cwe=tuple(cls.cwe),
                    owasp=tuple(cls.owasp),
                    risk=RiskClass(cls.risk),
                )
                for cls in classes
            )
            for asset_type, classes in payload.mappings.items()
        }
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid catalog: {exc}") from exc
    catalog = TestCatalog(version=payload.version, mappings=mappings)
    SqlAlchemyCatalogRepository(session).add_catalog(catalog)
    return _to_out(catalog)


@router.get("/latest", response_model=CatalogOut)
def get_latest_catalog(session: DbSession) -> CatalogOut:
    catalog = SqlAlchemyCatalogRepository(session).latest_catalog()
    if catalog is None:
        raise HTTPException(status_code=404, detail="no catalog available")
    return _to_out(catalog)


@router.get("/{version}", response_model=CatalogOut)
def get_catalog(version: str, session: DbSession) -> CatalogOut:
    catalog = SqlAlchemyCatalogRepository(session).get_catalog_by_version(version)
    if catalog is None:
        raise HTTPException(status_code=404, detail="catalog not found")
    return _to_out(catalog)
