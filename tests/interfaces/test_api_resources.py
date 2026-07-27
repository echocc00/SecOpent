"""Tests for the W1 resource API routers (projects/scopes/assessments).

These run against a real temporary SQLite database via the FastAPI TestClient,
exercising the DB-backed routers end-to-end (create -> persist -> read).
"""
from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from secopent.domain.adapters.contracts import Severity
from secopent.domain.assets.graph import AssetGraph
from secopent.domain.assets.models import (
    AssetEdge,
    AssetNode,
    AssetRelation,
    AssetType,
)
from secopent.domain.common.canonical import utc_now
from secopent.domain.evidence.models import Evidence, EvidenceLayer
from secopent.domain.findings.models import Finding, FindingStatus
from secopent.domain.intel.models import (
    AffectedProduct,
    DetectionMapping,
    ExploitationSignal,
    Vulnerability,
)
from secopent.domain.intel.provenance import Provenance
from secopent.domain.jobs.models import Job, JobStatus
from secopent.domain.policy.models import RiskClass
from secopent.domain.reports.models import Report, ReportSection, ReportStatus
from secopent.infrastructure.db.session import init_db
from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.repositories.sqlalchemy_assets import (
    SqlAlchemyAssetRepository,
)
from secopent.infrastructure.repositories.sqlalchemy_evidence import (
    SqlAlchemyEvidenceRepository,
)
from secopent.infrastructure.repositories.sqlalchemy_findings import (
    SqlAlchemyFindingRepository,
)
from secopent.infrastructure.repositories.sqlalchemy_intel import (
    SqlAlchemyIntelRepository,
    SqlAlchemyUpdateRepository,
)
from secopent.infrastructure.repositories.sqlalchemy_jobs import (
    SqlAlchemyJobRepository,
)
from secopent.infrastructure.repositories.sqlalchemy_reports import (
    SqlAlchemyReportRepository,
)
from secopent.interfaces.api.main import create_app


@pytest.fixture
def client(tmp_path) -> Iterator[TestClient]:  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "api.db")
    app = create_app(engine)
    with TestClient(app) as test_client:
        yield test_client


def test_openapi_spec_accessible(client: TestClient) -> None:
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    paths = resp.json()["paths"]
    assert "/projects" in paths
    assert "/scopes/draft" in paths
    assert "/assessments" in paths
    assert "/tools" in paths
    assert "/findings" in paths
    assert "/intel/search" in paths
    assert "/updates/active" in paths
    assert "/audit/events" in paths
    assert "/audit/verify" in paths
    assert "/plans" in paths
    assert "/approvals" in paths
    assert "/jobs" in paths
    assert "/assets" in paths
    assert "/evidence" in paths
    assert "/reports" in paths


def test_tools_lists_adapters(client: TestClient) -> None:
    resp = client.get("/tools")
    assert resp.status_code == 200
    tools = resp.json()
    keys = {t["key"] for t in tools}
    assert "nuclei" in keys
    assert "nmap" in keys
    assert "prowler" in keys
    nuclei = next(t for t in tools if t["key"] == "nuclei")
    assert nuclei["domain"] == "web"
    assert nuclei["digest"].startswith("sha256:")


def test_project_create_get_list(client: TestClient) -> None:
    created = client.post("/projects", json={"name": "Acme"})
    assert created.status_code == 201
    project = created.json()
    assert project["name"] == "Acme"
    assert project["status"] == "active"
    project_id = project["id"]

    fetched = client.get(f"/projects/{project_id}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == project_id

    listed = client.get("/projects")
    assert listed.status_code == 200
    assert any(p["id"] == project_id for p in listed.json())


def test_project_not_found(client: TestClient) -> None:
    assert client.get("/projects/nope").status_code == 404


def test_scope_freeze_and_get(client: TestClient) -> None:
    project = client.post("/projects", json={"name": "Acme"}).json()
    created = client.post(
        "/scopes/draft",
        json={"project_id": project["id"], "include": ["https://acme.test"]},
    )
    assert created.status_code == 201
    snapshot = created.json()
    assert snapshot["project_id"] == project["id"]
    # Scope normalization appends a trailing slash to a bare domain URL.
    assert "https://acme.test/" in snapshot["include"]
    assert snapshot["digest"].startswith("sha256:")

    fetched = client.get(f"/scopes/{snapshot['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == snapshot["id"]


def test_assessment_create_and_get(client: TestClient) -> None:
    project = client.post("/projects", json={"name": "Acme"}).json()
    scope = client.post(
        "/scopes/draft",
        json={"project_id": project["id"], "include": ["https://acme.test"]},
    ).json()
    created = client.post(
        "/assessments",
        json={"project_id": project["id"], "scope_snapshot_id": scope["id"]},
    )
    assert created.status_code == 201
    assessment = created.json()
    assert assessment["project_id"] == project["id"]
    assert assessment["scope_snapshot_id"] == scope["id"]
    assert assessment["status"] == "draft"

    fetched = client.get(f"/assessments/{assessment['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == assessment["id"]


def test_assessment_invalid_mode_422(client: TestClient) -> None:
    project = client.post("/projects", json={"name": "Acme"}).json()
    scope = client.post(
        "/scopes/draft",
        json={"project_id": project["id"], "include": ["https://acme.test"]},
    ).json()
    resp = client.post(
        "/assessments",
        json={
            "project_id": project["id"],
            "scope_snapshot_id": scope["id"],
            "mode": "bogus",
        },
    )
    assert resp.status_code == 422


# --- Findings (DB-backed, idempotent) ----------------------------------------


def test_finding_create_get_list(client: TestClient) -> None:
    created = client.post(
        "/findings",
        json={"title": "SQLi", "asset": "https://x.test/login", "severity": "high",
              "cwe": ["CWE-89"]},
    )
    assert created.status_code == 201
    finding = created.json()
    assert finding["id"].startswith("finding:")
    assert finding["severity"] == "high"
    assert finding["status"] == "draft"

    fetched = client.get(f"/findings/{finding['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["title"] == "SQLi"

    client.post("/findings", json={"title": "XSS", "asset": "https://x.test/"})
    listed = client.get("/findings")
    assert listed.status_code == 200
    assert len(listed.json()) == 2


def test_finding_unknown_404(client: TestClient) -> None:
    assert client.get("/findings/nope").status_code == 404


def test_finding_invalid_severity_422(client: TestClient) -> None:
    resp = client.post(
        "/findings",
        json={"title": "x", "asset": "https://x.test/", "severity": "bogus"},
    )
    assert resp.status_code == 422


def test_finding_idempotency_key_prevents_duplicate(client: TestClient) -> None:
    payload = {"title": "SQLi", "asset": "https://x.test/login"}
    first = client.post("/findings", json=payload, headers={"Idempotency-Key": "k1"})
    second = client.post("/findings", json=payload, headers={"Idempotency-Key": "k1"})
    assert first.json()["id"] == second.json()["id"]
    assert len(client.get("/findings").json()) == 1


# --- Audit (hash chain) ------------------------------------------------------


def test_audit_events_and_verify(client: TestClient) -> None:
    # Creating a scope records an audit event through the ScopeService chain.
    project = client.post("/projects", json={"name": "Acme"}).json()
    client.post(
        "/scopes/draft",
        json={"project_id": project["id"], "include": ["https://acme.test"]},
    )
    events = client.get("/audit/events")
    assert events.status_code == 200
    assert len(events.json()) >= 1

    verify = client.get("/audit/verify")
    assert verify.status_code == 200
    body = verify.json()
    assert body["valid"] is True
    assert body["event_count"] >= 1


# --- Intel (FTS5 search) -----------------------------------------------------


def _provenance(source: str = "nvd") -> Provenance:
    return Provenance(source=source, fetched_at=utc_now(), source_version="1.0")


def _vulnerability(canonical_id: str, description: str, cwe: tuple[str, ...]) -> Vulnerability:
    product = AffectedProduct(
        vendor="acme", product="widget", cpe=None, package=None,
        version_range=">=1.0,<2.0", fixed_versions=("2.0.1",),
    )
    mapping = DetectionMapping(
        vulnerability_id=canonical_id, case_version="2026.07",
        detection_type="network", risk=RiskClass.LOW, confidence=0.8,
    )
    signal = ExploitationSignal(
        kev=False, epss_score=0.1, public_exploit=False,
        ransomware=False, active_exploitation=False,
    )
    return Vulnerability(
        canonical_id=canonical_id, aliases=(canonical_id,), description=description,
        cvss={"nvd": (7.5, _provenance())}, cwe=cwe,
        references=("https://example.org/advisory",),
        published_at=datetime(2024, 6, 1, tzinfo=UTC),
        affected_products=(product,), exploitation_signal=signal,
        detection_mappings=(mapping,), provenance=_provenance(source="osv"),
    )


def test_intel_search_and_get(tmp_path) -> None:  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "intel.db")
    init_db(engine)
    with Session(engine) as session:
        SqlAlchemyIntelRepository(session).add_vulnerability(
            _vulnerability("CVE-2024-1234", "Heap overflow in acme widget.", ("CWE-787",))
        )
        session.commit()

    with TestClient(create_app(engine)) as intel_client:
        by_cve = intel_client.get("/intel/search", params={"cve": "CVE-2024-1234"})
        assert by_cve.status_code == 200
        results = by_cve.json()
        assert len(results) == 1
        assert results[0]["canonical_id"] == "CVE-2024-1234"
        # Multi-source CVSS preserved as source -> score.
        assert results[0]["cvss"]["nvd"] == 7.5

        fetched = intel_client.get("/intel/CVE-2024-1234")
        assert fetched.status_code == 200
        assert fetched.json()["affected_products"][0]["vendor"] == "acme"

        assert intel_client.get("/intel/CVE-0000-0000").status_code == 404


def test_intel_search_empty_query_returns_empty(tmp_path) -> None:  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "intel2.db")
    with TestClient(create_app(engine)) as intel_client:
        resp = intel_client.get("/intel/search")
        assert resp.status_code == 200
        assert resp.json() == []


# --- Updates (bundle state) --------------------------------------------------


def test_updates_active_empty_and_bundle_404(client: TestClient) -> None:
    active = client.get("/updates/active")
    assert active.status_code == 200
    assert active.json() == {"active_bundle_id": None, "bundle": None}
    assert client.get("/updates/bundles/nope").status_code == 404


def test_updates_active_bundle_after_seed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "updates.db")
    init_db(engine)
    with Session(engine) as session:
        repo = SqlAlchemyUpdateRepository(session)
        repo.add_bundle("bun-1", "2026.07.1", "sha256:abc", {"catalog": {}})
        repo.set_active_bundle("bun-1")
        session.commit()

    with TestClient(create_app(engine)) as updates_client:
        active = updates_client.get("/updates/active")
        assert active.status_code == 200
        body = active.json()
        assert body["active_bundle_id"] == "bun-1"
        assert body["bundle"]["version"] == "2026.07.1"

        fetched = updates_client.get("/updates/bundles/bun-1")
        assert fetched.status_code == 200
        assert fetched.json()["digest"] == "sha256:abc"


# --- Plans + Approvals (assessment workflow) ---------------------------------


def _bootstrap_assessment(client: TestClient) -> dict[str, str]:
    """Create a project + scope + assessment; return their ids."""
    project = client.post("/projects", json={"name": "Acme"}).json()
    scope = client.post(
        "/scopes/draft",
        json={"project_id": project["id"], "include": ["https://acme.test"]},
    ).json()
    assessment = client.post(
        "/assessments",
        json={"project_id": project["id"], "scope_snapshot_id": scope["id"]},
    ).json()
    return {"project": project["id"], "scope": scope["id"], "assessment": assessment["id"]}


def test_plan_create_and_get(client: TestClient) -> None:
    ids = _bootstrap_assessment(client)
    created = client.post(
        "/plans",
        json={
            "assessment_id": ids["assessment"],
            "steps": [
                {"key": "recon", "runner": "nuclei", "risk": "low"},
                {"key": "sqli", "runner": "nuclei", "risk": "active",
                 "dependencies": ["recon"]},
            ],
        },
    )
    assert created.status_code == 201
    plan = created.json()
    assert plan["assessment_id"] == ids["assessment"]
    assert plan["digest"].startswith("sha256:")
    assert {s["key"] for s in plan["steps"]} == {"recon", "sqli"}

    fetched = client.get(f"/plans/{plan['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == plan["id"]

    # The assessment moved to awaiting_approval with the plan attached.
    assessment = client.get(f"/assessments/{ids['assessment']}").json()
    assert assessment["status"] == "awaiting_approval"


def test_plan_unknown_assessment_404(client: TestClient) -> None:
    resp = client.post(
        "/plans",
        json={"assessment_id": "nope", "steps": [{"key": "a", "runner": "nuclei", "risk": "low"}]},
    )
    assert resp.status_code == 404


def test_plan_invalid_risk_422(client: TestClient) -> None:
    ids = _bootstrap_assessment(client)
    resp = client.post(
        "/plans",
        json={"assessment_id": ids["assessment"],
              "steps": [{"key": "a", "runner": "nuclei", "risk": "bogus"}]},
    )
    assert resp.status_code == 422


def test_plan_duplicate_step_key_422(client: TestClient) -> None:
    ids = _bootstrap_assessment(client)
    resp = client.post(
        "/plans",
        json={"assessment_id": ids["assessment"],
              "steps": [
                  {"key": "a", "runner": "nuclei", "risk": "low"},
                  {"key": "a", "runner": "nmap", "risk": "low"},
              ]},
    )
    assert resp.status_code == 422


def test_approval_create_and_get(client: TestClient) -> None:
    ids = _bootstrap_assessment(client)
    plan = client.post(
        "/plans",
        json={"assessment_id": ids["assessment"],
              "steps": [{"key": "recon", "runner": "nuclei", "risk": "low"}]},
    ).json()

    created = client.post(
        "/approvals",
        json={
            "assessment_id": ids["assessment"],
            "approved_by": "human-reviewer",
            "approved_risks": ["low", "active"],
            "approved_capabilities": ["network.scan"],
        },
    )
    assert created.status_code == 201
    approval = created.json()
    assert approval["approved_by"] == "human-reviewer"
    assert approval["plan_digest"] == plan["digest"]
    assert approval["scope_digest"].startswith("sha256:")
    assert approval["approved_risks"] == ["active", "low"]

    fetched = client.get(f"/approvals/{approval['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == approval["id"]

    # The assessment is now approved with the approval attached.
    assessment = client.get(f"/assessments/{ids['assessment']}").json()
    assert assessment["status"] == "approved"


def test_approval_without_plan_422(client: TestClient) -> None:
    ids = _bootstrap_assessment(client)
    resp = client.post(
        "/approvals",
        json={"assessment_id": ids["assessment"], "approved_by": "x"},
    )
    assert resp.status_code == 422


def test_approval_unknown_assessment_404(client: TestClient) -> None:
    resp = client.post("/approvals", json={"assessment_id": "nope", "approved_by": "x"})
    assert resp.status_code == 404


# --- Jobs (read-only) --------------------------------------------------------


def test_jobs_empty_list_and_404(client: TestClient) -> None:
    listed = client.get("/jobs")
    assert listed.status_code == 200
    assert listed.json() == []
    assert client.get("/jobs/nope").status_code == 404


def test_job_get_after_seed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "jobs.db")
    init_db(engine)
    with Session(engine) as session:
        SqlAlchemyJobRepository(session).add(
            Job(id="job-1", plan_step_key="web_app:TC-WEB-001",
                idempotency_key="idem-1", status=JobStatus.READY)
        )
        session.commit()

    with TestClient(create_app(engine)) as jobs_client:
        listed = jobs_client.get("/jobs")
        assert listed.status_code == 200
        assert len(listed.json()) == 1

        fetched = jobs_client.get("/jobs/job-1")
        assert fetched.status_code == 200
        assert fetched.json()["status"] == "ready"


# --- Assets (discovery graph) ------------------------------------------------


def test_asset_graph_round_trip(tmp_path) -> None:  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "assets.db")
    init_db(engine)
    domain = AssetNode(type=AssetType.DOMAIN, value="acme.test")
    ip = AssetNode(type=AssetType.IP, value="1.2.3.4")
    graph = (
        AssetGraph()
        .add_node(domain)
        .add_node(ip)
        .add_edge(AssetEdge(src=domain, dst=ip, rel=AssetRelation.RESOLVES_TO))
    )
    with Session(engine) as session:
        SqlAlchemyAssetRepository(session).save_graph(graph)
        session.commit()

    with TestClient(create_app(engine)) as assets_client:
        resp = assets_client.get("/assets")
        assert resp.status_code == 200
        body = resp.json()
        assert {(n["type"], n["value"]) for n in body["nodes"]} == {
            ("domain", "acme.test"),
            ("ip", "1.2.3.4"),
        }
        assert len(body["edges"]) == 1
        assert body["edges"][0]["rel"] == "resolves_to"


def test_asset_graph_empty(client: TestClient) -> None:
    resp = client.get("/assets")
    assert resp.status_code == 200
    assert resp.json() == {"nodes": [], "edges": []}


# --- Evidence (three-layer) --------------------------------------------------


def test_evidence_get_and_filter_by_finding(tmp_path) -> None:  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "evidence.db")
    init_db(engine)
    with Session(engine) as session:
        SqlAlchemyEvidenceRepository(session).add(
            Evidence(id="ev-1", layer=EvidenceLayer.RAW,
                     sha256="sha256:aaa", storage_uri="cas://ev-1")
        )
        SqlAlchemyEvidenceRepository(session).add(
            Evidence(id="ev-2", layer=EvidenceLayer.REDACTED,
                     sha256="sha256:bbb", storage_uri="cas://ev-2", source_id="ev-1")
        )
        SqlAlchemyFindingRepository(session).add(
            Finding(id="finding-1", fingerprint="sha256:fp", title="SQLi",
                    asset="https://x.test/", severity=Severity.HIGH,
                    evidence_ids=("ev-1", "ev-2"), status=FindingStatus.VALIDATED)
        )
        session.commit()

    with TestClient(create_app(engine)) as ev_client:
        one = ev_client.get("/evidence/ev-1")
        assert one.status_code == 200
        assert one.json()["layer"] == "raw"

        all_ev = ev_client.get("/evidence")
        assert len(all_ev.json()) == 2

        by_finding = ev_client.get("/evidence", params={"finding_id": "finding-1"})
        assert {e["id"] for e in by_finding.json()} == {"ev-1", "ev-2"}

        assert ev_client.get("/evidence/nope").status_code == 404
        assert ev_client.get(
            "/evidence", params={"finding_id": "nope"}
        ).status_code == 404


# --- Reports -----------------------------------------------------------------


def test_reports_list_and_get(tmp_path) -> None:  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "reports.db")
    init_db(engine)
    with Session(engine) as session:
        SqlAlchemyReportRepository(session).add(
            Report(
                id="rep-1", assessment_id="asm-1", title="Acme Assessment",
                sections=(ReportSection(name="summary", content="One finding."),),
                finding_count=1, coverage_rate=0.85, completeness_ok=True,
                status=ReportStatus.RENDERED, digest="sha256:rep",
            )
        )
        session.commit()

    with TestClient(create_app(engine)) as rep_client:
        listed = rep_client.get("/reports", params={"assessment_id": "asm-1"})
        assert listed.status_code == 200
        assert len(listed.json()) == 1
        assert listed.json()[0]["title"] == "Acme Assessment"

        fetched = rep_client.get("/reports/rep-1")
        assert fetched.status_code == 200
        assert fetched.json()["sections"][0]["name"] == "summary"

        assert rep_client.get("/reports/nope").status_code == 404
