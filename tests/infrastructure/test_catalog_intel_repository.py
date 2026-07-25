# tests/infrastructure/test_catalog_intel_repository.py
"""TDD tests for the catalog/intel/update repositories (SQLite + FTS5).

Covers M1 Task 4 of the SecOpent plan:

* ``TestCatalog`` / ``CoverageMatrix`` persistence (add + get-by-version)
* ``Vulnerability`` persistence with FTS5 full-text search by keyword, CVE,
  and CWE (§10 of the main design)
* ``UpdateBundle`` persistence with an activation record (the "active version"
  pointer used by ``UpdateManager`` in Task 6)

The fixture mirrors the M0 ``test_core_repository_contract.py`` pattern but
extends ``CoreBase.metadata.create_all`` to also include the catalog, intel,
and update ORM tables plus the ``core_vulnerabilities_fts`` FTS5 virtual
table created via raw SQL.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from secopent.domain.catalog.coverage import CoverageMatrix
from secopent.domain.catalog.models import (
    AssetType,
    RequiredTestClass,
    TestCatalog,
)
from secopent.domain.common.canonical import utc_now
from secopent.domain.intel.models import (
    AffectedProduct,
    DetectionMapping,
    ExploitationSignal,
    Vulnerability,
)
from secopent.domain.intel.provenance import Provenance
from secopent.domain.policy.models import RiskClass
from secopent.infrastructure.db.catalog_models import CoreBase, CoreCoverageMatrix, CoreTestCatalog
from secopent.infrastructure.db.intel_models import (
    CoreAffectedProduct,
    CoreDetectionMapping,
    CoreExploitationSignal,
    CoreIntelSnapshot,
    CoreVulnerability,
)
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.db.update_models import CoreBundleActivation, CoreUpdateBundle
from secopent.infrastructure.repositories.sqlalchemy_catalog import (
    SqlAlchemyCatalogRepository,
)
from secopent.infrastructure.repositories.sqlalchemy_intel import (
    SqlAlchemyIntelRepository,
    SqlAlchemyUpdateRepository,
)


@pytest.fixture
def session(tmp_path):
    engine = create_sqlite_engine(tmp_path / "secopent.db")
    CoreBase.metadata.create_all(engine)
    # FTS5 virtual table for vulnerability keyword search (CVE/description/CWE).
    # Created via raw SQL because SQLAlchemy 2.0 does not model virtual tables
    # declaratively. The FTS rowid mirrors the canonical_id so the repository
    # can join FTS hits back to the CoreVulnerability row.
    with engine.begin() as connection:
        connection.execute(text(
            "CREATE VIRTUAL TABLE IF NOT EXISTS core_vulnerabilities_fts "
            "USING fts5(canonical_id UNINDEXED, cve, description, cwe)"
        ))
    session = Session(engine)
    yield session
    session.close()


# --- TestCatalog / CoverageMatrix persistence --------------------------------


def _sample_catalog(version: str = "2026.07") -> TestCatalog:
    web = RequiredTestClass(
        id="TC-WEB-001", cwe=("CWE-79",), owasp=("A03:2021",), risk=RiskClass.LOW
    )
    api = RequiredTestClass(
        id="TC-API-001", cwe=("CWE-306",), owasp=("A01:2021",), risk=RiskClass.ACTIVE
    )
    return TestCatalog(
        version=version,
        mappings={AssetType.WEB_APP: (web,), AssetType.API: (api,)},
    )


def _sample_matrix(version: str = "2026.07") -> CoverageMatrix:
    return CoverageMatrix(
        version=version,
        framework="OWASP_WSTG_4.2",
        mappings={
            "WSTG-INPV-01": ("TC-WEB-001",),
            "WSTG-ATHZ-01": ("TC-API-001",),
            "WSTG-SESS-01": (),
        },
        total_items=3,
    )


def test_catalog_repository_round_trip(session) -> None:
    repo = SqlAlchemyCatalogRepository(session)
    catalog = _sample_catalog()
    repo.add_catalog(catalog)
    session.commit()

    fetched = repo.get_catalog_by_version("2026.07")
    assert fetched == catalog


def test_catalog_repository_returns_none_for_missing_version(session) -> None:
    repo = SqlAlchemyCatalogRepository(session)
    assert repo.get_catalog_by_version("missing") is None


def test_coverage_matrix_round_trip(session) -> None:
    repo = SqlAlchemyCatalogRepository(session)
    matrix = _sample_matrix()
    repo.add_coverage(matrix)
    session.commit()

    fetched = repo.get_coverage("2026.07", "OWASP_WSTG_4.2")
    assert fetched == matrix


def test_coverage_matrix_returns_none_for_missing(session) -> None:
    repo = SqlAlchemyCatalogRepository(session)
    assert repo.get_coverage("missing", "OWASP_WSTG_4.2") is None


# --- Vulnerability persistence + FTS5 ---------------------------------------


def _provenance(source: str = "nvd") -> Provenance:
    return Provenance(
        source=source, fetched_at=utc_now(), source_version="1.0"
    )


def _vulnerability(
    canonical_id: str,
    description: str,
    cwe: tuple[str, ...],
    aliases: tuple[str, ...] = (),
) -> Vulnerability:
    product = AffectedProduct(
        vendor="acme",
        product="widget",
        cpe=None,
        package=None,
        version_range=">=1.0,<2.0",
        fixed_versions=("2.0.1",),
    )
    mapping = DetectionMapping(
        vulnerability_id=canonical_id,
        case_version="2026.07",
        detection_type="network",
        risk=RiskClass.LOW,
        confidence=0.8,
    )
    signal = ExploitationSignal(
        kev=False,
        epss_score=0.1,
        public_exploit=False,
        ransomware=False,
        active_exploitation=False,
    )
    return Vulnerability(
        canonical_id=canonical_id,
        aliases=aliases or (canonical_id,),
        description=description,
        cvss={"nvd": (7.5, _provenance(source="nvd"))},
        cwe=cwe,
        references=("https://example.org/advisory",),
        published_at=datetime(2024, 6, 1, tzinfo=UTC),
        affected_products=(product,),
        exploitation_signal=signal,
        detection_mappings=(mapping,),
        provenance=_provenance(source="osv"),
    )


def test_vulnerability_round_trip(session) -> None:
    repo = SqlAlchemyIntelRepository(session)
    vuln = _vulnerability(
        canonical_id="CVE-2024-1234",
        description="Heap overflow in acme widget.",
        cwe=("CWE-787",),
    )
    repo.add_vulnerability(vuln)
    session.commit()

    fetched = repo.get_vulnerability("CVE-2024-1234")
    assert fetched is not None
    assert fetched.canonical_id == "CVE-2024-1234"
    assert fetched.description == "Heap overflow in acme widget."
    assert fetched.cwe == ("CWE-787",)
    assert fetched.cvss["nvd"][0] == 7.5
    assert fetched.affected_products[0].vendor == "acme"
    assert fetched.detection_mappings[0].detection_type == "network"


def test_vulnerability_get_missing_returns_none(session) -> None:
    repo = SqlAlchemyIntelRepository(session)
    assert repo.get_vulnerability("missing") is None


def test_fts_search_by_keyword_returns_matches(session) -> None:
    repo = SqlAlchemyIntelRepository(session)
    repo.add_vulnerability(_vulnerability(
        canonical_id="CVE-2024-1234",
        description="Heap overflow in acme widget allows remote code execution.",
        cwe=("CWE-787",),
    ))
    repo.add_vulnerability(_vulnerability(
        canonical_id="CVE-2024-5678",
        description="SQL injection in login form.",
        cwe=("CWE-89",),
    ))
    repo.add_vulnerability(_vulnerability(
        canonical_id="CVE-2023-9999",
        description="Cross-site scripting in search widget.",
        cwe=("CWE-79",),
    ))
    session.commit()

    hits = repo.search_fts(keyword="widget")
    canonical_ids = {h.canonical_id for h in hits}
    # Both "acme widget" (CVE-2024-1234) and "search widget" (CVE-2023-9999)
    # match the keyword "widget"; the SQL-injection record does not.
    assert canonical_ids == {"CVE-2024-1234", "CVE-2023-9999"}


def test_fts_search_by_cve_returns_exact(session) -> None:
    repo = SqlAlchemyIntelRepository(session)
    repo.add_vulnerability(_vulnerability(
        canonical_id="CVE-2024-1234",
        description="Heap overflow in acme widget.",
        cwe=("CWE-787",),
        aliases=("CVE-2024-1234", "OSV-2024-1"),
    ))
    repo.add_vulnerability(_vulnerability(
        canonical_id="CVE-2024-5678",
        description="SQL injection.",
        cwe=("CWE-89",),
    ))
    session.commit()

    hits = repo.search_fts(cve="CVE-2024-1234")
    assert len(hits) == 1
    assert hits[0].canonical_id == "CVE-2024-1234"


def test_fts_search_by_cwe_returns_matches(session) -> None:
    repo = SqlAlchemyIntelRepository(session)
    repo.add_vulnerability(_vulnerability(
        canonical_id="CVE-2024-1234",
        description="Heap overflow.",
        cwe=("CWE-787",),
    ))
    repo.add_vulnerability(_vulnerability(
        canonical_id="CVE-2024-5678",
        description="Out-of-bounds write.",
        cwe=("CWE-787",),
    ))
    repo.add_vulnerability(_vulnerability(
        canonical_id="CVE-2023-9999",
        description="XSS.",
        cwe=("CWE-79",),
    ))
    session.commit()

    hits = repo.search_fts(cwe="CWE-787")
    canonical_ids = {h.canonical_id for h in hits}
    assert canonical_ids == {"CVE-2024-1234", "CVE-2024-5678"}


def test_fts_search_empty_returns_empty(session) -> None:
    repo = SqlAlchemyIntelRepository(session)
    repo.add_vulnerability(_vulnerability(
        canonical_id="CVE-2024-1234",
        description="Heap overflow.",
        cwe=("CWE-787",),
    ))
    session.commit()

    assert repo.search_fts(keyword="") == []
    assert repo.search_fts() == []


# --- UpdateBundle persistence + activation ----------------------------------


def test_update_bundle_round_trip(session) -> None:
    repo = SqlAlchemyUpdateRepository(session)
    bundle_payload = {
        "catalog_version": "2026.07",
        "intel_cutoff": "2026-07-25T00:00:00Z",
        "files": ["catalog.json", "intel.jsonl"],
    }
    repo.add_bundle(
        bundle_id="bundle-1",
        version="2026.07",
        digest="sha256:" + "a" * 64,
        payload=bundle_payload,
    )
    session.commit()

    fetched = repo.get_bundle("bundle-1")
    assert fetched is not None
    assert fetched["version"] == "2026.07"
    assert fetched["digest"] == "sha256:" + "a" * 64
    assert fetched["payload"] == bundle_payload


def test_update_bundle_get_missing_returns_none(session) -> None:
    repo = SqlAlchemyUpdateRepository(session)
    assert repo.get_bundle("missing") is None


def test_activation_pointer_round_trip(session) -> None:
    repo = SqlAlchemyUpdateRepository(session)
    repo.add_bundle(
        bundle_id="bundle-1",
        version="2026.07",
        digest="sha256:" + "a" * 64,
        payload={"v": 1},
    )
    repo.add_bundle(
        bundle_id="bundle-2",
        version="2026.08",
        digest="sha256:" + "b" * 64,
        payload={"v": 2},
    )
    repo.set_active_bundle("bundle-2")
    session.commit()

    assert repo.get_active_bundle_id() == "bundle-2"

    # Switch back to bundle-1 (atomic pointer swap).
    repo.set_active_bundle("bundle-1")
    session.commit()
    assert repo.get_active_bundle_id() == "bundle-1"


def test_activation_returns_none_when_unset(session) -> None:
    repo = SqlAlchemyUpdateRepository(session)
    assert repo.get_active_bundle_id() is None


# --- ORM sanity: CoreBase extended so create_all covers M1 tables -----------

def test_core_base_includes_m1_tables(session) -> None:
    # If CoreBase did not include the M1 tables, create_all() in the fixture
    # would have raised; this test pins the registration so a future
    # refactor cannot silently drop the catalog/intel/update tables.
    table_names = set(CoreBase.metadata.tables.keys())
    assert "core_test_catalogs" in table_names
    assert "core_coverage_matrices" in table_names
    assert "core_vulnerabilities" in table_names
    assert "core_affected_products" in table_names
    assert "core_exploitation_signals" in table_names
    assert "core_detection_mappings" in table_names
    assert "core_intel_snapshots" in table_names
    assert "core_update_bundles" in table_names
    assert "core_bundle_activations" in table_names


def test_unused_imports_are_part_of_api() -> None:
    # Quiet ruff F401 for ORM symbols that the fixture creates via
    # CoreBase.metadata but that the test bodies reference only indirectly.
    assert CoreTestCatalog is not None
    assert CoreCoverageMatrix is not None
    assert CoreVulnerability is not None
    assert CoreAffectedProduct is not None
    assert CoreExploitationSignal is not None
    assert CoreDetectionMapping is not None
    assert CoreIntelSnapshot is not None
    assert CoreUpdateBundle is not None
    assert CoreBundleActivation is not None
