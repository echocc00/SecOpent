# tests/domain/test_peer_agents.py
"""Domain tests for peer agent models (integration spec §5 P0)."""
from __future__ import annotations

import pytest

from secopent.domain.common.errors import DomainValidationError
from secopent.domain.peer_agents.models import (
    PeerAgentBudget,
    PeerAgentDescriptor,
    PeerAgentFinding,
    PeerAgentReport,
    PeerAgentRun,
    PeerAgentTrustLevel,
    PeerRunStatus,
    RejectionReason,
)


def _budget() -> PeerAgentBudget:
    return PeerAgentBudget(max_wall_seconds=1800, max_cost_units=100.0)


def _descriptor() -> PeerAgentDescriptor:
    return PeerAgentDescriptor(
        name="strix",
        version="1.4.1",
        license="Apache-2.0",
        trust_level=PeerAgentTrustLevel.ADOPTED_EXTERNAL,
        capabilities=("web", "api"),
        cost_class="llm_tokens",
        default_budget=_budget(),
    )


class TestPeerAgentBudget:
    def test_rejects_negative_wall_seconds(self) -> None:
        with pytest.raises(DomainValidationError):
            PeerAgentBudget(max_wall_seconds=-1, max_cost_units=10.0)

    def test_rejects_negative_cost_units(self) -> None:
        with pytest.raises(DomainValidationError):
            PeerAgentBudget(max_wall_seconds=60, max_cost_units=-0.1)

    def test_accepts_zero_budget(self) -> None:
        budget = PeerAgentBudget(max_wall_seconds=0, max_cost_units=0.0)
        assert budget.max_wall_seconds == 0


class TestPeerAgentDescriptor:
    def test_rejects_empty_name(self) -> None:
        with pytest.raises(DomainValidationError):
            PeerAgentDescriptor(
                name="", version="1.0", license="MIT",
                trust_level=PeerAgentTrustLevel.UNTRUSTED,
                capabilities=(), cost_class="llm_tokens",
                default_budget=_budget(),
            )

    def test_is_frozen(self) -> None:
        descriptor = _descriptor()
        with pytest.raises(AttributeError):
            descriptor.name = "other"  # type: ignore[misc]


class TestPeerAgentRun:
    def test_defaults_to_pending_with_no_timestamps(self) -> None:
        run = PeerAgentRun(
            id="run-1", agent_name="strix", agent_version="1.4.1",
            assessment_id="asmt-1", targets=("http://host.docker.internal:3000",),
            budget=_budget(), permit_id="permit-1",
        )
        assert run.status is PeerRunStatus.PENDING
        assert run.started_at is None and run.finished_at is None

    def test_rejects_empty_targets(self) -> None:
        with pytest.raises(DomainValidationError):
            PeerAgentRun(
                id="run-1", agent_name="strix", agent_version="1.4.1",
                assessment_id="asmt-1", targets=(), budget=_budget(),
                permit_id="permit-1",
            )


class TestPeerAgentFinding:
    def test_requires_provenance_fields(self) -> None:
        with pytest.raises(DomainValidationError):
            PeerAgentFinding(
                id="f-1", run_id="", agent_name="strix", title="SQLi",
                asset="http://t", severity_hint="high",
            )

    def test_defaults_empty_hint_tuples(self) -> None:
        finding = PeerAgentFinding(
            id="f-1", run_id="run-1", agent_name="strix",
            title="SQLi in /login", asset="http://host.docker.internal:3000",
            severity_hint="high",
        )
        assert finding.cwe == () and finding.owasp == () and finding.cve == ()


class TestPeerAgentReport:
    def test_holds_findings_and_costs(self) -> None:
        finding = PeerAgentFinding(
            id="f-1", run_id="run-1", agent_name="strix",
            title="t", asset="http://t", severity_hint="low",
        )
        report = PeerAgentReport(
            run_id="run-1", findings=(finding,),
            wall_seconds=120.5, cost_units=3.2, exit_code=0,
        )
        assert len(report.findings) == 1


class TestEnums:
    def test_trust_levels(self) -> None:
        assert PeerAgentTrustLevel.ADOPTED_EXTERNAL.value == "adopted_external_agent"
        assert PeerAgentTrustLevel.UNTRUSTED.value == "untrusted"

    def test_rejection_reasons_cover_spec_gates(self) -> None:
        # spec §4: 目录外噪音拒收 + scope 越界拒收 + 解析失败
        assert {r.value for r in RejectionReason} == {
            "out_of_scope", "out_of_catalog", "parse_error",
        }
