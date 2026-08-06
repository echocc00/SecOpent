# tests/infrastructure/test_ptai_backend.py
"""PtaiBackend: invocation building + permissive report parsing (Phase 2.10).

Covers:
- build_invocation: exchange mount + env + input.json (run_id, targets, scope
  instruction); missing LLM secret raises KeyError (config error);
- parse_report: empty out/ yields empty findings; one-finding JSON fixture
  yields one finding; malformed artifact yields empty findings (never raises);
- registration: default off, on when enable_ptai=True (composition root +
  the SECOPTENT_ENABLE_PTAI env flag in main.py).

These run on Windows - no real ptai install needed (all fakes/fixtures).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from secopent.domain.peer_agents.models import (
    PeerAgentBudget,
    PeerAgentDescriptor,
    PeerAgentRun,
    PeerAgentTrustLevel,
)
from secopent.infrastructure.adapters.base import ContainerResult
from secopent.infrastructure.peer_agents.composition import (
    PTAI_VERSION,
    create_peer_agent_service,
    ptai_descriptor,
)
from secopent.infrastructure.peer_agents.ptai_backend import PtaiBackend

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "peer_reports"


def _descriptor() -> PeerAgentDescriptor:
    return PeerAgentDescriptor(
        name="ptai", version=PTAI_VERSION, license="MIT",
        trust_level=PeerAgentTrustLevel.ADOPTED_EXTERNAL,
        capabilities=("web", "network"), cost_class="llm_tokens",
        default_budget=PeerAgentBudget(max_wall_seconds=3600, max_cost_units=200),
        image_digest="secopent/peer-worker-ptai:1.1.0",  # tag-only (digest="")
    )


def _run() -> PeerAgentRun:
    return PeerAgentRun(
        id="ptai-run-1", agent_name="ptai", agent_version=PTAI_VERSION,
        assessment_id="asmt-1",
        targets=("http://host.docker.internal:3000",),
        budget=PeerAgentBudget(max_wall_seconds=3600, max_cost_units=200),
        permit_id="p-1",
    )


class TestBuildInvocation:
    def test_invocation_carries_exchange_mount_and_env(self, tmp_path: Path) -> None:
        backend = PtaiBackend(
            llm_provider="openai/gpt-4o-mini",
            secret_lookup={"LLM_API_KEY": "sk-test"},
        )
        invocation = backend.build_invocation(_run(), _descriptor(), tmp_path)
        assert invocation.image_digest == _descriptor().image_digest
        # An exchange dir is mounted into the container.
        assert any(k == "/exchange" or "exchange" in v for k, v in invocation.mounts.items())
        assert invocation.env["PTAI_LLM"] == "openai/gpt-4o-mini"
        assert invocation.env["LLM_API_KEY"] == "sk-test"
        # input.json carries run_id, targets, and the scope instruction.
        input_file = tmp_path / "exchange" / "input.json"
        assert input_file.exists()
        payload = json.loads(input_file.read_text(encoding="utf-8"))
        assert payload["run_id"] == "ptai-run-1"
        assert payload["targets"] == ["http://host.docker.internal:3000"]
        assert "scope" in payload["instruction"].lower() or "only" in payload["instruction"].lower()

    def test_missing_llm_secret_raises_keyerror(self, tmp_path: Path) -> None:
        backend = PtaiBackend(llm_provider="x", secret_lookup={})
        with pytest.raises(KeyError):
            backend.build_invocation(_run(), _descriptor(), tmp_path)


class TestParseReport:
    def _write_input(self, workdir: Path) -> None:
        exchange = workdir / "exchange"
        exchange.mkdir(parents=True, exist_ok=True)
        (exchange / "input.json").write_text(
            json.dumps({"run_id": "ptai-run-1", "targets": []}),
            encoding="utf-8",
        )

    def test_empty_out_yields_empty_findings(self, tmp_path: Path) -> None:
        self._write_input(tmp_path)
        (tmp_path / "exchange" / "out").mkdir(parents=True)
        backend = PtaiBackend(llm_provider="x", secret_lookup={"LLM_API_KEY": "k"})
        result = ContainerResult(
            stdout="", stderr="", exit_code=0,
            artifacts_dir=tmp_path / "exchange" / "out",
        )
        report = backend.parse_report(result, tmp_path)
        assert report.findings == ()
        assert report.exit_code == 0
        assert report.run_id == "ptai-run-1"

    def test_one_finding_json_fixture_parsed(self, tmp_path: Path) -> None:
        self._write_input(tmp_path)
        out = tmp_path / "exchange" / "out"
        out.mkdir(parents=True)
        (out / "findings.json").write_text(
            (_FIXTURES / "ptai_findings.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        backend = PtaiBackend(llm_provider="x", secret_lookup={"LLM_API_KEY": "k"})
        result = ContainerResult(stdout="", stderr="", exit_code=0, artifacts_dir=out)
        report = backend.parse_report(result, tmp_path)
        assert len(report.findings) == 1
        finding = report.findings[0]
        assert finding.agent_name == "ptai"
        assert finding.run_id == "ptai-run-1"
        assert "SQL Injection" in finding.title
        assert finding.asset == "http://host.docker.internal:3000/login"
        assert finding.severity_hint == "high"
        assert "CWE-89" in finding.cwe

    def test_malformed_artifact_yields_empty_not_crash(self, tmp_path: Path) -> None:
        self._write_input(tmp_path)
        out = tmp_path / "exchange" / "out"
        out.mkdir(parents=True)
        (out / "broken.txt").write_text(
            (_FIXTURES / "ptai_malformed.txt").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        backend = PtaiBackend(llm_provider="x", secret_lookup={"LLM_API_KEY": "k"})
        result = ContainerResult(
            stdout="", stderr="boom", exit_code=1, artifacts_dir=out,
        )
        report = backend.parse_report(result, tmp_path)
        assert report.findings == ()
        assert report.exit_code == 1

    def test_missing_out_dir_yields_empty(self, tmp_path: Path) -> None:
        # input.json exists but out/ was never created (e.g. container died
        # before writing anything). parse_report must not crash.
        self._write_input(tmp_path)
        backend = PtaiBackend(llm_provider="x", secret_lookup={"LLM_API_KEY": "k"})
        result = ContainerResult(
            stdout="", stderr="", exit_code=1, artifacts_dir=tmp_path,
        )
        report = backend.parse_report(result, tmp_path)
        assert report.findings == ()


class TestPtaiDescriptor:
    def test_descriptor_identity(self) -> None:
        desc = ptai_descriptor()
        assert desc.name == "ptai"
        assert desc.version == PTAI_VERSION
        assert desc.license == "MIT"
        assert desc.trust_level is PeerAgentTrustLevel.ADOPTED_EXTERNAL
        assert "web" in desc.capabilities
        assert "network" in desc.capabilities

    def test_descriptor_image_digest_empty_until_linux_build(self) -> None:
        # digest is empty until the first Linux build of peer-worker-ptai
        # records a manifest-list digest (A4 spike: Linux-only deps).
        desc = ptai_descriptor()
        # _image_ref returns tag-only when digest is empty.
        assert desc.image_digest == "secopent/peer-worker-ptai:1.1.0"


class TestRegistrationBehindFlag:
    """ptai is opt-in behind enable_ptai (default off), mirroring shannon."""

    def _make_service(self, tmp_path: Path, **kwargs: object):
        from secopent.application.audit import AuditService
        from secopent.infrastructure.peer_agents.in_memory_peer_runs import (
            InMemoryPeerRunRepository,
        )

        return create_peer_agent_service(
            audit=AuditService(repo=_FakeAuditRepo()),
            runs=InMemoryPeerRunRepository(),
            llm_provider="openai/gpt-4o-mini",
            secret_lookup={"LLM_API_KEY": "sk-test"},
            workdir_root=tmp_path,
            **kwargs,
        )

    def test_default_registry_has_no_ptai(self, tmp_path: Path) -> None:
        service = self._make_service(tmp_path)
        assert service.registry.get("ptai") is None

    def test_enabled_registers_ptai(self, tmp_path: Path) -> None:
        service = self._make_service(tmp_path, enable_ptai=True)
        desc = service.registry.get("ptai")
        assert desc is not None
        assert desc.name == "ptai"
        assert desc.license == "MIT"
        assert desc.version == PTAI_VERSION
        assert desc.trust_level is PeerAgentTrustLevel.ADOPTED_EXTERNAL

    def test_disabled_when_flag_false(self, tmp_path: Path) -> None:
        service = self._make_service(tmp_path, enable_ptai=False)
        assert service.registry.get("ptai") is None


class _FakeAuditRepo:
    """Minimal audit repo for composition tests (mirrors test_peer_composition)."""

    def __init__(self) -> None:
        self._events: list[object] = []

    def add(self, event: object) -> None:
        self._events.append(event)

    def list_events(self) -> list[object]:
        return list(self._events)

    def last_hash(self) -> str:
        from secopent.domain.audit.models import GENESIS_HASH
        return GENESIS_HASH
