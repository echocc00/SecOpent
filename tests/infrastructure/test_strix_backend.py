# tests/infrastructure/test_strix_backend.py
"""StrixBackend: invocation building + report collection (P2 Task 2)."""
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
from secopent.infrastructure.peer_agents.strix_backend import StrixBackend


def _descriptor() -> PeerAgentDescriptor:
    return PeerAgentDescriptor(
        name="strix", version="1.4.1", license="Apache-2.0",
        trust_level=PeerAgentTrustLevel.ADOPTED_EXTERNAL,
        capabilities=("web", "api"), cost_class="llm_tokens",
        default_budget=PeerAgentBudget(max_wall_seconds=1800, max_cost_units=100),
        image_digest="secopent/peer-worker-strix@sha256:" + "b" * 64,
    )


def _run() -> PeerAgentRun:
    return PeerAgentRun(
        id="peer-run-42", agent_name="strix", agent_version="1.4.1",
        assessment_id="asmt-1",
        targets=("http://host.docker.internal:3000",),
        budget=PeerAgentBudget(max_wall_seconds=1800, max_cost_units=100),
        permit_id="p-1",
    )


class TestBuildInvocation:
    def test_invocation_carries_exchange_mount_and_env(self, tmp_path) -> None:
        backend = StrixBackend(
            llm_provider="openai/gpt-x",
            secret_lookup={"LLM_API_KEY": "sk-test"},
        )
        invocation = backend.build_invocation(_run(), _descriptor(), tmp_path)
        assert invocation.image_digest == _descriptor().image_digest
        assert "/exchange" in invocation.mounts.values() or any(
            "exchange" in v for v in invocation.mounts.values()
        )
        assert invocation.env["STRIX_LLM"] == "openai/gpt-x"
        assert invocation.env["LLM_API_KEY"] == "sk-test"
        # Scope injection via input.json (entrypoint reads it; targets stay
        # out of argv too)
        input_file = tmp_path / "exchange" / "input.json"
        assert input_file.exists()
        payload = json.loads(input_file.read_text(encoding="utf-8"))
        assert payload["targets"] == ["http://host.docker.internal:3000"]
        assert payload["run_id"] == "peer-run-42"

    def test_missing_llm_secret_raises_keyerror(self, tmp_path) -> None:
        backend = StrixBackend(llm_provider="openai/gpt-x", secret_lookup={})
        with pytest.raises(KeyError):
            backend.build_invocation(_run(), _descriptor(), tmp_path)


class TestParseReport:
    def test_parses_findings_from_exchange_out(self, tmp_path) -> None:
        exchange_out = tmp_path / "exchange" / "out"
        exchange_out.mkdir(parents=True)
        fixture = (
            Path(__file__).resolve().parents[1]
            / "fixtures" / "peer_reports" / "strix_vulnerabilities.json"
        )
        (exchange_out / "vulnerabilities.json").write_text(
            fixture.read_text(encoding="utf-8"), encoding="utf-8"
        )
        (exchange_out / "run.json").write_text(
            '{"llm_usage": {"total_cost_usd": 1.25}}', encoding="utf-8"
        )
        # Also write input.json so _run_id_from_input works
        (tmp_path / "exchange" / "input.json").write_text(
            '{"run_id": "peer-run-42", "targets": []}', encoding="utf-8"
        )
        backend = StrixBackend(llm_provider="x", secret_lookup={"LLM_API_KEY": "k"})
        result = ContainerResult(stdout="", stderr="", exit_code=0, artifacts_dir=exchange_out)
        report = backend.parse_report(result, tmp_path)
        assert report.exit_code == 0
        assert len(report.findings) == 3
        assert report.cost_units == pytest.approx(1.25)

    def test_missing_report_yields_empty_findings_not_crash(self, tmp_path) -> None:
        (tmp_path / "exchange" / "out").mkdir(parents=True)
        (tmp_path / "exchange" / "input.json").write_text(
            '{"run_id": "r", "targets": []}', encoding="utf-8"
        )
        backend = StrixBackend(llm_provider="x", secret_lookup={"LLM_API_KEY": "k"})
        result = ContainerResult(
            stdout="", stderr="boom", exit_code=1,
            artifacts_dir=tmp_path / "exchange" / "out",
        )
        report = backend.parse_report(result, tmp_path)
        assert report.findings == ()
        assert report.exit_code == 1
