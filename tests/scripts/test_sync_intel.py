# tests/scripts/test_sync_intel.py
"""TDD tests for the intel sync CLI (P3 §3.4-1).

No real network: the OSV client is backed by ``httpx.MockTransport``. The
round-trip test persists to a real temp SQLite file (FTS5 included) and then
re-opens it to prove ``GET /intel/search`` would return the synced CVEs.
"""
from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from sqlalchemy.orm import Session

from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.intel_sources import OsvClient
from secopent.infrastructure.repositories.sqlalchemy_intel import (
    SqlAlchemyIntelRepository,
)
from secopent.scripts.sync_intel import main, sync_from_osv


def _osv_record(cve: str, summary: str) -> dict[str, Any]:
    return {
        "id": cve,
        "aliases": [f"GHSA-{cve.lower()}"],
        "summary": summary,
        "published": "2024-01-01T00:00:00Z",
        "references": [{"type": "WEB", "url": "https://example.com"}],
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "acme-lib"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}
                ],
            }
        ],
    }


_VULNS = [
    _osv_record("CVE-2024-0001", "SQL injection in login form"),
    _osv_record("CVE-2024-0002", "Cross-site scripting in profile page"),
]


def _client() -> OsvClient:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        if body.get("watermark"):
            return httpx.Response(200, json={"vulns": []})
        return httpx.Response(200, json={"vulns": _VULNS})

    return OsvClient(transport=httpx.MockTransport(handler))


def _search(db_path, **kwargs):
    engine = create_sqlite_engine(db_path)
    with Session(engine) as session:
        return SqlAlchemyIntelRepository(session).search_fts(**kwargs)


def test_sync_roundtrip_populates_fts(tmp_path, capsys):
    db = tmp_path / "intel.db"
    rc = main(["--source", "osv", "--limit", "10", "--db", str(db)], client=_client())
    assert rc == 0
    assert "synced 2 vulnerabilities" in capsys.readouterr().out

    # Re-open the persisted store: a keyword search hits the FTS5 description.
    hits = _search(db, keyword="SQL")
    assert [v.canonical_id for v in hits] == ["CVE-2024-0001"]

    xss = _search(db, keyword="scripting")
    assert [v.canonical_id for v in xss] == ["CVE-2024-0002"]

    # CVE lookup by id also works.
    by_cve = _search(db, cve="CVE-2024-0001")
    assert len(by_cve) == 1


def test_sync_limit_slices_results(tmp_path):
    db = tmp_path / "intel.db"
    rc = main(["--source", "osv", "--limit", "1", "--db", str(db)], client=_client())
    assert rc == 0
    # Only the first record lands.
    assert len(_search(db, keyword="SQL")) == 1
    assert _search(db, keyword="scripting") == []


def test_sync_is_idempotent(tmp_path):
    db = tmp_path / "intel.db"
    client = _client()
    main(["--source", "osv", "--limit", "10", "--db", str(db)], client=client)
    main(["--source", "osv", "--limit", "10", "--db", str(db)], client=client)
    # Re-syncing the same feed must not duplicate FTS hits.
    assert len(_search(db, keyword="SQL")) == 1


def test_sync_rejects_unknown_source(tmp_path):
    with pytest.raises(SystemExit):
        main(["--source", "nvd", "--db", str(tmp_path / "x.db")], client=_client())


def test_sync_from_osv_negative_limit_raises(tmp_path):
    engine = create_sqlite_engine(tmp_path / "intel.db")
    from secopent.infrastructure.db.session import init_db

    init_db(engine)
    with Session(engine) as session, pytest.raises(ValueError):
        sync_from_osv(session, _client(), limit=-1)
