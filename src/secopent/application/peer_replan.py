# src/secopent/application/peer_replan.py
"""Reactive re-planning proposals from peer agent discoveries (spec D4①).

When a peer agent reports findings on assets not in the original plan, this
module generates PlanVersionProposal objects. Proposals NEVER auto-apply -
they queue for human approval through the existing Approval workflow. This
preserves the M4 DoD invariant: 'Agent 追加动作生成新 Plan Version'.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from .peer_agents import PeerRunOutcome


@dataclass(frozen=True, slots=True)
class PlanVersionProposal:
    """A proposed addition to the assessment plan from peer discoveries.

    ``approved`` defaults to False; the proposal must be explicitly approved
    before it takes effect. ``subjects`` is a sorted tuple of newly discovered
    asset identities.
    """

    run_id: str
    reason: str
    subjects: tuple[str, ...]
    approved: bool = field(default=False)
    proposed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


def _normalize_asset(asset: str) -> str:
    """Strip trailing slashes for comparison."""
    return asset.rstrip("/")


def propose_replan_from_outcome(
    outcome: PeerRunOutcome,
    *,
    planned_assets: tuple[str, ...],
) -> tuple[PlanVersionProposal, ...]:
    """Generate re-plan proposals for assets discovered by the peer agent.

    Returns one proposal with reason ``peer_discovered_asset`` if any observed
    asset was not in the planned set (after normalizing trailing slashes).
    Returns empty tuple if all observed assets were already planned.
    """
    planned_normalized = {_normalize_asset(a) for a in planned_assets}
    new_assets: set[str] = set()
    for observation in outcome.observations:
        normalized = _normalize_asset(observation.asset_identity)
        if normalized not in planned_normalized:
            new_assets.add(normalized)
    if not new_assets:
        return ()
    return (
        PlanVersionProposal(
            run_id=outcome.run.id,
            reason="peer_discovered_asset",
            subjects=tuple(sorted(new_assets)),
        ),
    )
