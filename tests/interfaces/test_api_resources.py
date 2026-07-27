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
from secopent.domain.catalog.models import (
    AssetType as CatalogAssetType,
)
from secopent.domain.catalog.models import (
    RequiredTestClass,
    TestCatalog,
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
from secopent.infrastructure.repositories.sqlalchemy_catalog import (
    SqlAlchemyCatalogRepository,
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
    assert "/cases" in paths
    assert "/appmodels" in paths


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


def test_scope_limits_round_trip(client: TestClient) -> None:
    project = client.post("/projects", json={"name": "Acme"}).json()
    created = client.post(
        "/scopes/draft",
        json={
            "project_id": project["id"],
            "include": ["https://acme.test"],
            "requests_per_second": 10.0,
            "concurrency": 8,
            "max_requests": 100_000,
        },
    )
    assert created.status_code == 201
    limits = created.json()["limits"]
    assert limits == {
        "requests_per_second": 10.0,
        "concurrency": 8,
        "max_requests": 100_000,
    }


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


def test_assessment_list_and_filter(client: TestClient) -> None:
    project = client.post("/projects", json={"name": "Acme"}).json()
    scope = client.post(
        "/scopes/draft",
        json={"project_id": project["id"], "include": ["https://acme.test"]},
    ).json()
    client.post(
        "/assessments",
        json={"project_id": project["id"], "scope_snapshot_id": scope["id"]},
    )
    listed = client.get("/assessments")
    assert listed.status_code == 200
    assert len(listed.json()) == 1

    filtered = client.get("/assessments", params={"project_id": project["id"]})
    assert len(filtered.json()) == 1
    assert client.get("/assessments", params={"project_id": "other"}).json() == []


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


def test_generate_plan_from_catalog(tmp_path) -> None:  # type: ignore[no-untyped-def]
    engine = create_sqlite_engine(tmp_path / "genplan.db")
    init_db(engine)
    with Session(engine) as session:
        SqlAlchemyCatalogRepository(session).add_catalog(
            TestCatalog(
                version="2026.07",
                mappings={
                    CatalogAssetType.WEB_APP: (
                        RequiredTestClass(
                            id="TC-WEB-001", cwe=("CWE-79",),
                            owasp=("A03:2021",), risk=RiskClass.LOW,
                        ),
                    ),
                },
            )
        )
        session.commit()

    with TestClient(create_app(engine)) as client:
        project = client.post("/projects", json={"name": "Acme"}).json()
        scope = client.post(
            "/scopes/draft",
            json={"project_id": project["id"], "include": ["https://acme.test"]},
        ).json()
        assessment = client.post(
            "/assessments",
            json={"project_id": project["id"], "scope_snapshot_id": scope["id"]},
        ).json()

        resp = client.post(f"/assessments/{assessment['id']}/plans")
        assert resp.status_code == 201
        plan = resp.json()
        assert len(plan["steps"]) >= 1
        assert plan["steps"][0]["key"].startswith("web_app:")
        # The assessment moves to awaiting_approval with the plan attached.
        fetched = client.get(f"/assessments/{assessment['id']}").json()
        assert fetched["status"] == "awaiting_approval"


def test_generate_plan_no_catalog_409(client: TestClient) -> None:
    ids = _bootstrap_assessment(client)
    resp = client.post(f"/assessments/{ids['assessment']}/plans")
    assert resp.status_code == 409


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


def test_finding_filters(client: TestClient) -> None:
    client.post("/findings", json={"title": "a", "asset": "https://x.test/",
                                   "severity": "high", "assessment_id": "asm-1"})
    client.post("/findings", json={"title": "b", "asset": "https://x.test/",
                                   "severity": "low", "assessment_id": "asm-2"})

    by_assessment = client.get("/findings", params={"assessment_id": "asm-1"})
    assert len(by_assessment.json()) == 1
    assert by_assessment.json()[0]["title"] == "a"

    by_severity = client.get("/findings", params={"severity": "low"})
    assert len(by_severity.json()) == 1
    assert by_severity.json()[0]["title"] == "b"


def test_finding_oracle_verdict(client: TestClient) -> None:
    finding = client.post(
        "/findings", json={"title": "SQLi", "asset": "https://x.test/login"}
    ).json()
    assert finding["oracle_verdict"] == "pending"

    verdict = client.post(
        f"/findings/{finding['id']}/verdict", json={"verdict": "confirmed"}
    )
    assert verdict.status_code == 200
    assert verdict.json()["oracle_verdict"] == "confirmed"

    confirmed = client.get("/findings", params={"oracle_verdict": "confirmed"})
    assert len(confirmed.json()) == 1

    bad = client.post(f"/findings/{finding['id']}/verdict", json={"verdict": "bogus"})
    assert bad.status_code == 422


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


def _assessment_awaiting_approval(client: TestClient) -> str:
    """Bootstrap an assessment with a plan attached (-> awaiting_approval)."""
    ids = _bootstrap_assessment(client)
    client.post(
        "/plans",
        json={"assessment_id": ids["assessment"],
              "steps": [{"key": "recon", "runner": "nuclei", "risk": "low"}]},
    )
    return ids["assessment"]


def test_approval_pending_then_approve(client: TestClient) -> None:
    assessment_id = _assessment_awaiting_approval(client)

    pending = client.get("/approvals/pending")
    assert pending.status_code == 200
    assert len(pending.json()) == 1
    assert pending.json()[0]["assessment_id"] == assessment_id
    assert pending.json()[0]["plan_digest"]

    client.post(
        "/approvals",
        json={"assessment_id": assessment_id, "approved_by": "human",
              "approved_risks": ["low"]},
    )
    assert client.get("/approvals/pending").json() == []

    history = client.get("/approvals/history")
    assert len(history.json()) == 1
    assert history.json()[0]["decision"] == "approved"
    assert history.json()[0]["decided_by"] == "human"


def test_approval_reject_with_reason(client: TestClient) -> None:
    assessment_id = _assessment_awaiting_approval(client)

    rejected = client.post(
        "/approvals/reject",
        json={"assessment_id": assessment_id, "rejected_by": "human",
              "reason": "scope too broad"},
    )
    assert rejected.status_code == 201
    assert rejected.json()["decision"] == "rejected"

    assessment = client.get(f"/assessments/{assessment_id}").json()
    assert assessment["status"] == "rejected"

    history = client.get("/approvals/history")
    assert len(history.json()) == 1
    assert history.json()[0]["reason"] == "scope too broad"


def test_approval_reject_requires_reason(client: TestClient) -> None:
    assessment_id = _assessment_awaiting_approval(client)
    resp = client.post(
        "/approvals/reject",
        json={"assessment_id": assessment_id, "rejected_by": "human", "reason": "  "},
    )
    assert resp.status_code == 422


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


# --- Cases (CaseStudio lifecycle + LLM boundary) -----------------------------


def _case_payload(case_id: str = "case-sqli", risk: str = "low") -> dict[str, object]:
    return {
        "id": case_id,
        "version": "1.0.0",
        "author": "analyst",
        "risk": risk,
        "target_type": "web_app",
        "case_schema": "secopent-case/v1",
        "steps": [{"id": "s1", "action": "http.request", "spec": {"method": "GET"}}],
        "cwe": ["CWE-89"],
    }


def test_case_full_human_lifecycle(client: TestClient) -> None:
    created = client.post("/cases", json=_case_payload())
    assert created.status_code == 201
    assert created.json()["status"] == "draft"

    assert client.post("/cases/case-sqli/validate").json()["status"] == "validated"
    assert client.post(
        "/cases/case-sqli/review", json={"actor_role": "human"}
    ).json()["status"] == "reviewed"

    signed = client.post("/cases/case-sqli/sign", json={"actor_role": "human"})
    assert signed.json()["status"] == "signed"
    assert signed.json()["signature"]  # server-held Ed25519 signature applied

    published = client.post("/cases/case-sqli/publish", json={"actor_role": "human"})
    assert published.json()["status"] == "published"


def test_case_agent_cannot_sign(client: TestClient) -> None:
    client.post("/cases", json=_case_payload())
    client.post("/cases/case-sqli/validate")
    client.post("/cases/case-sqli/review", json={"actor_role": "human"})
    # The LLM boundary: an agent may not sign (human-only).
    resp = client.post("/cases/case-sqli/sign", json={"actor_role": "agent"})
    assert resp.status_code == 403


def test_case_out_of_order_transition_409(client: TestClient) -> None:
    client.post("/cases", json=_case_payload())
    # draft -> publish skips validate/review/sign.
    resp = client.post("/cases/case-sqli/publish", json={"actor_role": "human"})
    assert resp.status_code == 409


def test_case_risk_undeclared_422(client: TestClient) -> None:
    # A GET step computes to Low; declaring passive understates it.
    client.post("/cases", json=_case_payload(risk="passive"))
    resp = client.post("/cases/case-sqli/validate")
    assert resp.status_code == 422


def test_case_deny_pattern_422(client: TestClient) -> None:
    payload = _case_payload()
    payload["steps"] = [{"id": "s1", "action": "os.shell", "spec": {}}]  # type: ignore[index]
    client.post("/cases", json=payload)
    resp = client.post("/cases/case-sqli/validate")
    assert resp.status_code == 422


def test_case_not_found_404(client: TestClient) -> None:
    assert client.get("/cases/nope").status_code == 404


def test_case_list(client: TestClient) -> None:
    client.post("/cases", json=_case_payload("case-a"))
    client.post("/cases", json=_case_payload("case-b"))
    listed = client.get("/cases")
    assert listed.status_code == 200
    assert {c["id"] for c in listed.json()} == {"case-a", "case-b"}


def test_case_invalid_risk_422(client: TestClient) -> None:
    resp = client.post("/cases", json=_case_payload(risk="bogus"))
    assert resp.status_code == 422


def test_case_yaml_round_trip(client: TestClient) -> None:
    payload = _case_payload()
    payload["yaml"] = "id: case-sqli\ninfo:\n  severity: low\n"  # type: ignore[index]
    created = client.post("/cases", json=payload)
    assert created.status_code == 201
    fetched = client.get("/cases/case-sqli").json()
    assert fetched["yaml"].startswith("id: case-sqli")


def test_case_analyze_risk_ok(client: TestClient) -> None:
    client.post("/cases", json=_case_payload())  # GET step -> computed low
    analysis = client.post("/cases/case-sqli/analyze")
    assert analysis.status_code == 200
    body = analysis.json()
    assert body["computed_risk"] == "low"
    assert body["risk_ok"] is True
    assert body["denied"] is False
    assert body["errors"] == []


def test_case_analyze_risk_mismatch(client: TestClient) -> None:
    # GET computes low but declared passive understates it.
    client.post("/cases", json=_case_payload(risk="passive"))
    body = client.post("/cases/case-sqli/analyze").json()
    assert body["risk_ok"] is False
    assert body["computed_risk"] == "low"
    assert len(body["errors"]) == 1


def test_case_analyze_denied_pattern(client: TestClient) -> None:
    payload = _case_payload()
    payload["steps"] = [{"id": "s1", "action": "os.shell", "spec": {}}]  # type: ignore[index]
    client.post("/cases", json=payload)
    body = client.post("/cases/case-sqli/analyze").json()
    assert body["denied"] is True
    assert body["computed_risk"] is None


# --- Signing keys (server-held Ed25519) --------------------------------------


def test_signing_keys_default_and_create(client: TestClient) -> None:
    listed = client.get("/signing-keys")
    assert listed.status_code == 200
    keys = listed.json()
    assert len(keys) == 1  # the default key created at startup
    assert keys[0]["name"] == "default"
    assert keys[0]["public_key"]  # public key exposed
    assert "private" not in keys[0]  # private material never exposed

    created = client.post("/signing-keys", json={"name": "release"})
    assert created.status_code == 201
    assert len(client.get("/signing-keys").json()) == 2


def test_case_sign_with_explicit_key(client: TestClient) -> None:
    key_id = client.get("/signing-keys").json()[0]["key_id"]
    client.post("/cases", json=_case_payload())
    client.post("/cases/case-sqli/validate")
    client.post("/cases/case-sqli/review", json={"actor_role": "human"})

    signed = client.post(
        "/cases/case-sqli/sign",
        json={"actor_role": "human", "key_id": key_id},
    )
    assert signed.status_code == 200
    assert signed.json()["status"] == "signed"
    assert signed.json()["signature"]

    bad = client.post(
        "/cases/case-sqli/sign",
        json={"actor_role": "human", "key_id": "secret:does-not-exist"},
    )
    assert bad.status_code == 404


# --- AppModels (model-driven logic + LLM boundary) ---------------------------


def _appmodel_payload(app_id: str = "shop", version: str = "1.0") -> dict[str, object]:
    return {
        "app_id": app_id,
        "version": version,
        "states": ["cart_empty", "cart_has_items", "ordered"],
        "transitions": [
            {"id": "add", "from_state": "cart_empty", "to_state": "cart_has_items",
             "endpoint": "POST /cart", "params": ["item_id"], "idempotent": False}
        ],
        "invariants": [{"id": "inv1", "expr": "cart.total >= 0"}],
        "fields": [{"name": "qty", "type": "int", "range": [1, 100],
                    "trusted_source": "server"}],
        "roles": [{"id": "buyer", "capabilities": ["cart.add", "order.create"]}],
        "out_of_scope_rules": ["payment gateway internals"],
    }


def test_appmodel_full_human_lifecycle(client: TestClient) -> None:
    created = client.post("/appmodels", json=_appmodel_payload())
    assert created.status_code == 201
    body = created.json()
    assert body["status"] == "draft"
    assert body["digest"].startswith("sha256:")

    validated = client.post(
        "/appmodels/shop/1.0/validate", json={"actor_role": "human"}
    )
    assert validated.json()["status"] == "human_validated"

    signed = client.post("/appmodels/shop/1.0/sign", json={"actor_role": "human"})
    assert signed.json()["status"] == "signed"
    assert signed.json()["signature"]  # server-held Ed25519 signature applied

    fetched = client.get("/appmodels/shop/1.0")
    assert fetched.status_code == 200
    assert fetched.json()["status"] == "signed"


def test_appmodel_round_trips_nested_fields(client: TestClient) -> None:
    client.post("/appmodels", json=_appmodel_payload())
    fetched = client.get("/appmodels/shop/1.0").json()
    assert fetched["transitions"][0]["endpoint"] == "POST /cart"
    assert fetched["invariants"][0]["expr"] == "cart.total >= 0"
    assert fetched["fields"][0]["range"] == [1, 100]
    assert fetched["fields"][0]["trusted_source"] == "server"
    assert fetched["roles"][0]["capabilities"] == ["cart.add", "order.create"]


def test_appmodel_agent_cannot_validate(client: TestClient) -> None:
    client.post("/appmodels", json=_appmodel_payload())
    resp = client.post("/appmodels/shop/1.0/validate", json={"actor_role": "agent"})
    assert resp.status_code == 403


def test_appmodel_agent_cannot_sign(client: TestClient) -> None:
    client.post("/appmodels", json=_appmodel_payload())
    client.post("/appmodels/shop/1.0/validate", json={"actor_role": "human"})
    resp = client.post("/appmodels/shop/1.0/sign", json={"actor_role": "agent"})
    assert resp.status_code == 403


def test_appmodel_sign_before_validate_409(client: TestClient) -> None:
    client.post("/appmodels", json=_appmodel_payload())
    resp = client.post("/appmodels/shop/1.0/sign", json={"actor_role": "human"})
    assert resp.status_code == 409


def test_appmodel_not_found_404(client: TestClient) -> None:
    assert client.get("/appmodels/nope/1.0").status_code == 404


def test_appmodel_list(client: TestClient) -> None:
    client.post("/appmodels", json=_appmodel_payload("shop-a"))
    client.post("/appmodels", json=_appmodel_payload("shop-b"))
    listed = client.get("/appmodels")
    assert listed.status_code == 200
    assert {m["app_id"] for m in listed.json()} == {"shop-a", "shop-b"}


def test_appmodel_update_in_place(client: TestClient) -> None:
    client.post("/appmodels", json=_appmodel_payload())
    payload = _appmodel_payload()
    payload["invariants"] = [{"id": "inv2", "expr": "qty <= 100"}]  # type: ignore[index]
    updated = client.put("/appmodels/shop/1.0", json=payload)
    assert updated.status_code == 200
    assert updated.json()["status"] == "draft"
    assert updated.json()["invariants"][0]["expr"] == "qty <= 100"


def test_appmodel_update_signed_409(client: TestClient) -> None:
    _sign_model(client)  # shop@1.0 -> signed
    resp = client.put("/appmodels/shop/1.0", json=_appmodel_payload())
    assert resp.status_code == 409


def test_appmodel_revise_bumps_version(client: TestClient) -> None:
    _sign_model(client)  # shop@1.0 signed (immutable)
    revised = client.post("/appmodels/shop/1.0/revise", json=_appmodel_payload())
    assert revised.status_code == 201
    assert revised.json()["version"] == "1.1"
    assert revised.json()["status"] == "draft"
    # The signed source version is untouched.
    assert client.get("/appmodels/shop/1.0").json()["status"] == "signed"


def test_appmodel_llm_proposed(client: TestClient) -> None:
    payload = _appmodel_payload("llm-shop")
    payload["llm_proposed"] = True  # type: ignore[index]
    created = client.post("/appmodels", json=payload)
    assert created.json()["status"] == "llm_proposed"


# --- Test generation (model-driven logic tests) ------------------------------


def _sign_model(client: TestClient, app_id: str = "shop") -> None:
    client.post("/appmodels", json=_appmodel_payload(app_id))
    client.post(f"/appmodels/{app_id}/1.0/validate", json={"actor_role": "human"})
    signed = client.post(f"/appmodels/{app_id}/1.0/sign", json={"actor_role": "human"})
    assert signed.json()["status"] == "signed"


def test_generate_tests_from_signed_model(client: TestClient) -> None:
    _sign_model(client)
    resp = client.post("/appmodels/shop/1.0/generate-tests")
    assert resp.status_code == 201
    cases = resp.json()
    assert len(cases) >= 1
    # Every generated case is model-generated and (ACTIVE) stops at validated.
    for case in cases:
        assert case["origin"] == "model_generated"
        assert case["status"] == "validated"
    # The invariant "cart.total >= 0" yields an invariant-violation test.
    test_classes = {
        c["steps"][0]["spec"]["test_class"] for c in cases
    }
    assert "invariant_violation" in test_classes


def test_generate_tests_is_idempotent(client: TestClient) -> None:
    _sign_model(client)
    first = {c["id"] for c in client.post("/appmodels/shop/1.0/generate-tests").json()}
    second = {c["id"] for c in client.post("/appmodels/shop/1.0/generate-tests").json()}
    assert first == second  # same model -> same signatures -> same case ids


def test_generate_tests_requires_signed_model(client: TestClient) -> None:
    client.post("/appmodels", json=_appmodel_payload())  # draft, not signed
    resp = client.post("/appmodels/shop/1.0/generate-tests")
    assert resp.status_code == 409


def test_generate_tests_missing_model_404(client: TestClient) -> None:
    assert client.post("/appmodels/nope/1.0/generate-tests").status_code == 404
