# tests/application/test_peer_reactive_replan.py
"""Reactive re-planning: peer discoveries propose plan additions (spec D4①).

Peer findings that reference assets NOT yet in the Assessment's plan generate
a PlanVersionProposal - NEVER an automatic plan change: proposals queue for
human approval (M4 DoD: 'Agent 追加动作生成新 Plan Version').
"""
from __future__ import annotations

from secopent.application.peer_agents import PeerRunOutcome
from secopent.application.peer_replan import (
    PlanVersionProposal,
    propose_replan_from_outcome,
)
from secopent.domain.adapters.contracts import (
    AdapterSource,
    CoverageDomain,
    Observation,
    Severity,
)
from secopent.domain.peer_agents.models import (
    PeerAgentBudget,
    PeerAgentRun,
    PeerRunStatus,
)


def _make_run(
    *, targets: tuple[str, ...] = ("http://host.docker.internal:3000",)
) -> PeerAgentRun:
    return PeerAgentRun(
        id="run-replan-1",
        agent_name="strix",
        agent_version="1.4.1",
        assessment_id="asmt-1",
        targets=targets,
        budget=PeerAgentBudget(max_wall_seconds=3600, max_cost_units=200.0),
        permit_id="p-1",
        status=PeerRunStatus.COMPLETED,
    )


def _observation_for_asset(asset: str) -> Observation:
    """Build a minimal peer:strix Observation for the given asset."""
    return Observation(
        external_id=f"strix-run-{asset}",
        asset_identity=asset,
        source=AdapterSource(
            name="peer:strix", version="1.4.1", template_version="na"
        ),
        rule_id=f"strix-run-{asset}",
        rule_version="1.4.1",
        coverage_domain=CoverageDomain.WEB,
        title=f"Finding on {asset}",
        severity=Severity.HIGH,
        confidence=0.5,
        cwe=("CWE-89",),
    )


def _outcome_with_assets(
    *, planned: tuple[str, ...], observed: tuple[str, ...]
) -> PeerRunOutcome:
    run = _make_run(targets=planned)
    observations = tuple(_observation_for_asset(a) for a in observed)
    return PeerRunOutcome(run=run, observations=observations, rejected=())


class TestReplanProposal:
    def test_new_asset_triggers_proposal(self) -> None:
        outcome = _outcome_with_assets(
            planned=("http://host.docker.internal:3000",),
            observed=(
                "http://host.docker.internal:3000",
                "http://internal-api.docker:8080",
            ),
        )
        proposals = propose_replan_from_outcome(
            outcome, planned_assets=outcome.run.targets
        )
        assert len(proposals) == 1
        proposal = proposals[0]
        assert isinstance(proposal, PlanVersionProposal)
        assert proposal.reason == "peer_discovered_asset"
        assert "http://internal-api.docker:8080" in proposal.subjects
        assert proposal.approved is False  # must not auto-approve

    def test_no_new_asset_no_proposal(self) -> None:
        outcome = _outcome_with_assets(
            planned=("http://host.docker.internal:3000",),
            observed=("http://host.docker.internal:3000",),
        )
        assert (
            propose_replan_from_outcome(
                outcome, planned_assets=outcome.run.targets
            )
            == ()
        )

    def test_trailing_slash_normalized(self) -> None:
        """Assets differing only by trailing slash are treated as the same."""
        outcome = _outcome_with_assets(
            planned=("http://host.docker.internal:3000",),
            observed=("http://host.docker.internal:3000/",),
        )
        assert (
            propose_replan_from_outcome(
                outcome, planned_assets=outcome.run.targets
            )
            == ()
        )

    def test_multiple_new_assets_sorted_in_subjects(self) -> None:
        outcome = _outcome_with_assets(
            planned=("http://host.docker.internal:3000",),
            observed=(
                "http://host.docker.internal:3000",
                "http://z-service:9090",
                "http://a-service:8080",
            ),
        )
        proposals = propose_replan_from_outcome(
            outcome, planned_assets=outcome.run.targets
        )
        assert len(proposals) == 1
        assert proposals[0].subjects == (
            "http://a-service:8080",
            "http://z-service:9090",
        )

    def test_empty_observations_no_proposal(self) -> None:
        outcome = PeerRunOutcome(
            run=_make_run(), observations=(), rejected=()
        )
        assert (
            propose_replan_from_outcome(
                outcome, planned_assets=outcome.run.targets
            )
            == ()
        )
