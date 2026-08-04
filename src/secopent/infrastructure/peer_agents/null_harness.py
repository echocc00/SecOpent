"""NullPeerAgentHarness: no-op harness for graceful degradation (W4-A T1).

Returned by the composition root when Docker or peer-agent images are
unavailable, so ``PeerAgentService.launch`` degrades to an empty
``PeerAgentReport`` instead of failing at container launch. Mirrors the
``NullModelBackend`` / ``NullInteractshTransport`` fallback pattern: the
service stays constructible and the API surface returns empty results
rather than 500ing.
"""
from __future__ import annotations

from ...domain.peer_agents.models import (
    PeerAgentDescriptor,
    PeerAgentReport,
    PeerAgentRun,
)


class NullPeerAgentHarness:
    """PeerAgentHarness that produces no findings and terminates nothing."""

    def execute(
        self, run: PeerAgentRun, descriptor: PeerAgentDescriptor
    ) -> PeerAgentReport:
        return PeerAgentReport(
            run_id=run.id,
            findings=(),
            wall_seconds=0.0,
            cost_units=0.0,
            exit_code=0,
        )

    def terminate(self, run_id: str) -> bool:
        return False
