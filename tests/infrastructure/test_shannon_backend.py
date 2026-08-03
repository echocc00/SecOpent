# tests/infrastructure/test_shannon_backend.py
"""ShannonBackend: invocation + repo working-copy isolation (P3 Task 2)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from secopent.domain.peer_agents.models import (
    PeerAgentBudget, PeerAgentDescriptor, PeerAgentRun, PeerAgentTrustLevel,
)
from secopent.infrastructure.adapters.base import ContainerResult
from secopent.infrastructure.peer_agents.shannon_backend import ShannonBackend


def _descriptor() -> PeerAgentDescriptor:
    return PeerAgentDescriptor(
        name="shannon", version="2.0", license="AGPL-3.0",
        trust_level=PeerAgentTrustLevel.ADOPTED_EXTERNAL,
        capabilities=("web", "whitebox"), cost_class="llm_tokens",
        default_budget=PeerAgentBudget(max_wall_seconds=3600, max_cost_units=200),
        image_digest="keygraph/shannon@sha256:" + "c" * 64,
    )


def _run() -> PeerAgentRun:
    return PeerAgentRun(
        id="peer-run-s1", agent_name="shannon", agent_version="2.0",
        assessment_id="asmt-1", targets=("http://host.docker.internal:3000",),
        budget=PeerAgentBudget(max_wall_seconds=3600, max_cost_units=200),
        permit_id="p-1",
    )


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "target-repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("print('hi')", encoding="utf-8")
    (repo / ".git").mkdir()
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")
    return repo


class TestRepoIsolation:
    def test_build_invocation_copies_repo_not_mounts_original(self, tmp_path) -> None:
        repo = _make_repo(tmp_path)
        backend = ShannonBackend(
            repo_path=repo, llm_key_name="ANTHROPIC_API_KEY",
            secret_lookup={"ANTHROPIC_API_KEY": "sk-ant-test"},
        )
        invocation = backend.build_invocation(_run(), _descriptor(), tmp_path / "work")
        # 挂载的宿主路径必须是工作副本，不得是原 repo
        mounted_sources = list(invocation.mounts.values())
        assert all(str(repo) not in src for src in mounted_sources)
        copy_root = next(
            src for src in mounted_sources if "repo-copy" in src
        )
        assert Path(copy_root, "src", "app.py").exists()  # 副本内容可见

    def test_env_carries_llm_key_and_web_url(self, tmp_path) -> None:
        repo = _make_repo(tmp_path)
        backend = ShannonBackend(
            repo_path=repo, llm_key_name="ANTHROPIC_API_KEY",
            secret_lookup={"ANTHROPIC_API_KEY": "sk-ant-test"},
        )
        invocation = backend.build_invocation(_run(), _descriptor(), tmp_path / "work")
        assert invocation.env["ANTHROPIC_API_KEY"] == "sk-ant-test"
        assert invocation.env["WEB_URL"] == "http://host.docker.internal:3000"


class TestParseReport:
    def test_parses_deliverables_from_copy(self, tmp_path) -> None:
        work = tmp_path / "work"
        copy = work / "repo-copy"
        (copy / ".shannon" / "deliverables").mkdir(parents=True)
        # Simulate build_invocation having written the run_id marker
        work.mkdir(parents=True, exist_ok=True)
        (work / "run_id.txt").write_text("peer-run-s1", encoding="utf-8")
        fixture = (
            Path(__file__).resolve().parents[1] / "fixtures" / "peer_reports"
            / "shannon_injection_deliverable.md"
        )
        (copy / ".shannon" / "deliverables" / "injection_analysis_deliverable.md").write_text(
            fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )
        backend = ShannonBackend(
            repo_path=tmp_path, llm_key_name="K", secret_lookup={"K": "v"},
        )
        result = ContainerResult(stdout="", stderr="", exit_code=0, artifacts_dir=copy)
        report = backend.parse_report(result, work)
        assert report.exit_code == 0
        assert len(report.findings) == 2

    def test_no_deliverables_yields_empty_report(self, tmp_path) -> None:
        work = tmp_path / "work"
        (work / "repo-copy").mkdir(parents=True)
        (work / "run_id.txt").write_text("peer-run-s1", encoding="utf-8")
        backend = ShannonBackend(
            repo_path=tmp_path, llm_key_name="K", secret_lookup={"K": "v"},
        )
        result = ContainerResult(stdout="", stderr="", exit_code=1, artifacts_dir=work / "repo-copy")
        report = backend.parse_report(result, work)
        assert report.findings == ()
