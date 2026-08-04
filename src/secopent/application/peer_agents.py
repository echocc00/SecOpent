# src/secopent/application/peer_agents.py
"""PeerAgentService: govern external autonomous pentest agents (spec §4-§5).

Peer agents are LOW-TRUST DISCOVERY SOURCES. The service enforces, in order:
registry membership, trust level, launch scope, budget caps, then normalizes
reported findings through the deterministic scope + catalog gates before they
may join the Assessment's Observations. Findings never skip the oracle: this
service only produces candidate Observations (LLM边界).

The harness Protocol is inline (same convention as emergency_stop.py) so the
application layer stays free of Docker coupling.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from ..domain.adapters.contracts import Observation
from ..domain.catalog.models import AssetType, TestCatalog
from ..domain.peer_agents.models import (
    PeerAgentDescriptor,
    PeerAgentNotRegistered,
    PeerAgentReport,
    PeerAgentRun,
    PeerAgentTrustDenied,
    PeerAgentTrustLevel,
    PeerRunScopeViolation,
    PeerRunStatus,
    RejectedFinding,
    RejectionReason,
)
from ..domain.peer_agents.normalize import (
    finding_in_scope,
    hits_required_catalog,
    normalize_finding,
)
from ..domain.peer_agents.registry import PeerAgentRegistry
from ..domain.scope.models import ScopeSnapshot
from .audit import AuditService
from .ports.repositories import PeerRunRepository


@runtime_checkable
class PeerAgentHarness(Protocol):
    """Execution surface for peer agents (infra implements, tests fake)."""

    def execute(
        self, run: PeerAgentRun, descriptor: PeerAgentDescriptor
    ) -> PeerAgentReport: ...

    def terminate(self, run_id: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class PeerRunOutcome:
    """Result of one peer run: the run record plus gated results."""

    run: PeerAgentRun
    observations: tuple[Observation, ...]
    rejected: tuple[RejectedFinding, ...]


class PeerAgentService:
    """Launch, budget-gate, normalize, and stop peer agent runs."""

    def __init__(
        self,
        *,
        registry: PeerAgentRegistry,
        harness: PeerAgentHarness,
        audit: AuditService,
        runs: PeerRunRepository,
    ) -> None:
        self._registry = registry
        self._harness = harness
        self._audit = audit
        self._runs = runs

    @property
    def registry(self) -> PeerAgentRegistry:
        """Read-only access to the peer agent registry."""
        return self._registry

    def get_run(self, run_id: str) -> PeerAgentRun | None:
        """Look up a peer run by id (None if not found)."""
        return self._runs.get(run_id)

    def list_runs(self, assessment_id: str) -> tuple[PeerAgentRun, ...]:
        """List peer runs for an assessment (newest-first stable order)."""
        return self._runs.list_for_assessment(assessment_id)

    def launch(
        self,
        *,
        assessment_id: str,
        agent_name: str,
        targets: tuple[str, ...],
        scope: ScopeSnapshot,
        catalog: TestCatalog,
        asset_type: AssetType,
        actor: str,
        permit_id: str,
    ) -> PeerRunOutcome:
        descriptor = self._registry.get(agent_name)
        if descriptor is None:
            raise PeerAgentNotRegistered(
                f"peer agent not registered: {agent_name}"
            )
        if descriptor.trust_level is not PeerAgentTrustLevel.ADOPTED_EXTERNAL:
            raise PeerAgentTrustDenied(
                f"peer agent trust level denies execution: {agent_name} "
                f"({descriptor.trust_level.value})"
            )
        for target in targets:
            if not (scope.includes_url(target) or scope.includes_domain(target)):
                raise PeerRunScopeViolation(
                    f"peer launch target outside scope: {target}"
                )

        run = PeerAgentRun(
            id=f"peer-run-{uuid.uuid4().hex[:12]}",
            agent_name=descriptor.name,
            agent_version=descriptor.version,
            assessment_id=assessment_id,
            targets=targets,
            budget=descriptor.default_budget,
            permit_id=permit_id,
            status=PeerRunStatus.RUNNING,
            started_at=datetime.now(UTC),
        )
        self._runs.add(run)
        self._audit.record(
            actor=actor,
            action="peer_run.launch",
            resource_type="peer_agent_run",
            resource_id=run.id,
            payload={
                "agent": descriptor.name,
                "targets": list(targets),
                "permit_id": permit_id,
            },
        )

        try:
            report = self._harness.execute(run, descriptor)
        except Exception:
            self._finish(run, PeerRunStatus.FAILED, actor)
            raise

        status = PeerRunStatus.COMPLETED
        over_wall = report.wall_seconds > run.budget.max_wall_seconds
        over_cost = report.cost_units > run.budget.max_cost_units
        if over_wall or over_cost:
            status = PeerRunStatus.BUDGET_EXCEEDED
            self._audit.record(
                actor=actor,
                action="peer_run.budget_exceeded",
                resource_type="peer_agent_run",
                resource_id=run.id,
                payload={
                    "wall_seconds": report.wall_seconds,
                    "cost_units": report.cost_units,
                },
            )
        # Evidence preservation: findings produced before the breach are
        # still normalized (spec §12 - 证据不被静默丢弃).

        observations, rejected = self._normalize(
            report, run, scope, catalog, asset_type
        )
        finished = self._finish(run, status, actor)
        self._audit.record(
            actor=actor,
            action="peer_run.collect",
            resource_type="peer_agent_run",
            resource_id=run.id,
            payload={
                "findings_total": len(report.findings),
                "observations_accepted": len(observations),
                "findings_rejected": len(rejected),
                "rejection_reasons": [r.reason.value for r in rejected],
                "exit_code": report.exit_code,
            },
        )
        return PeerRunOutcome(
            run=finished, observations=observations, rejected=rejected
        )

    def stop(self, *, run_id: str, actor: str, reason: str) -> bool:
        """Terminate an active peer run (Emergency Stop path, spec §5)."""
        run = self._runs.get(run_id)
        if run is None:
            return False
        terminated = self._harness.terminate(run_id)
        self._finish(run, PeerRunStatus.STOPPED, actor)
        self._audit.record(
            actor=actor,
            action="peer_run.stop",
            resource_type="peer_agent_run",
            resource_id=run_id,
            payload={"reason": reason, "terminated": terminated},
        )
        return terminated

    # -- internals ---------------------------------------------------------

    def _normalize(
        self,
        report: PeerAgentReport,
        run: PeerAgentRun,
        scope: ScopeSnapshot,
        catalog: TestCatalog,
        asset_type: AssetType,
    ) -> tuple[tuple[Observation, ...], tuple[RejectedFinding, ...]]:
        observations: list[Observation] = []
        rejected: list[RejectedFinding] = []
        for finding in report.findings:
            if not finding_in_scope(finding, scope):
                rejected.append(
                    RejectedFinding(
                        finding=finding,
                        reason=RejectionReason.OUT_OF_SCOPE,
                        detail=f"asset outside scope: {finding.asset}",
                    )
                )
                continue
            if not hits_required_catalog(finding, catalog, asset_type):
                rejected.append(
                    RejectedFinding(
                        finding=finding,
                        reason=RejectionReason.OUT_OF_CATALOG,
                        detail="CWE/OWASP intersects no required test class",
                    )
                )
                continue
            observations.append(normalize_finding(finding, run))
        return tuple(observations), tuple(rejected)

    def _finish(
        self, run: PeerAgentRun, status: PeerRunStatus, actor: str
    ) -> PeerAgentRun:
        finished = PeerAgentRun(
            id=run.id,
            agent_name=run.agent_name,
            agent_version=run.agent_version,
            assessment_id=run.assessment_id,
            targets=run.targets,
            budget=run.budget,
            permit_id=run.permit_id,
            status=status,
            started_at=run.started_at,
            finished_at=datetime.now(UTC),
        )
        self._runs.save(finished)
        return finished
