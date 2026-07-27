# src/secopent/interfaces/api/routers/intel.py
"""Intel resource router (Phase A P1, W1): the vulnerability knowledge layer.

Read-only surface over ``SqlAlchemyIntelRepository``:
- ``GET /intel/search`` - FTS5 keyword/CVE/CWE search;
- ``GET /intel/{canonical_id}`` - fetch one canonical vulnerability record.

The multi-source CVSS map is preserved as ``source -> score`` (the platform
never picks a "winner"; downstream policy decides which score to honour).
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ....domain.intel.models import Vulnerability
from ....infrastructure.repositories.sqlalchemy_intel import SqlAlchemyIntelRepository
from ..deps import DbSession
from ..schemas import (
    AffectedProductOut,
    ExploitationSignalOut,
    VulnerabilityOut,
)

router = APIRouter(prefix="/intel", tags=["intel"])


def _to_out(vuln: Vulnerability) -> VulnerabilityOut:
    signal = vuln.exploitation_signal
    return VulnerabilityOut(
        canonical_id=vuln.canonical_id,
        aliases=list(vuln.aliases),
        description=vuln.description,
        cvss={source: score for source, (score, _prov) in vuln.cvss.items()},
        cwe=list(vuln.cwe),
        references=list(vuln.references),
        published_at=vuln.published_at,
        affected_products=[
            AffectedProductOut(
                vendor=p.vendor,
                product=p.product,
                cpe=p.cpe,
                package=p.package,
                version_range=p.version_range,
                fixed_versions=list(p.fixed_versions),
            )
            for p in vuln.affected_products
        ],
        exploitation_signal=ExploitationSignalOut(
            kev=signal.kev,
            epss_score=signal.epss_score,
            public_exploit=signal.public_exploit,
            ransomware=signal.ransomware,
            active_exploitation=signal.active_exploitation,
        ),
        digest=vuln.digest,
    )


@router.get("/search", response_model=list[VulnerabilityOut])
def search_intel(
    session: DbSession,
    keyword: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
) -> list[VulnerabilityOut]:
    repo = SqlAlchemyIntelRepository(session)
    vulns = repo.search_fts(keyword=keyword, cve=cve, cwe=cwe)
    return [_to_out(v) for v in vulns]


@router.get("/{canonical_id}", response_model=VulnerabilityOut)
def get_vulnerability(canonical_id: str, session: DbSession) -> VulnerabilityOut:
    vuln = SqlAlchemyIntelRepository(session).get_vulnerability(canonical_id)
    if vuln is None:
        raise HTTPException(status_code=404, detail="vulnerability not found")
    return _to_out(vuln)
