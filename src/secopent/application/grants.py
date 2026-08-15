"""GrantService: the grant lifecycle owner (v0.6.0 spec §3.3).

Creation and revocation are HUMAN-ONLY (an agent can never mint its own
authorization - that would defeat the whole model). ``authorize`` is the
pure gate the approval flow calls: it returns a (allowed, reason) decision
without mutating anything, so the caller (AssessmentService.approve/start)
decides whether to proceed or raise.

``list_active`` is the read surface an agent uses to discover what it may
run (MCP grant_list) - it never reveals the grant's creation/revocation
machinery.
"""
from __future__ import annotations

from datetime import datetime

from ..domain.assessments.models import PlanStep
from ..domain.common.canonical import utc_now
from ..domain.grants.errors import GrantNotFoundError
from ..domain.grants.models import EngagementGrant
from ..domain.policy.models import RiskClass
from ..domain.scope.models import ScopeSnapshot
from .assessments import AssessmentPermissionError
from .ports.grants import GrantRepository


class GrantDecision:
    """Outcome of grant authorization (immutable)."""

    __slots__ = ("allowed", "reason")

    def __init__(self, allowed: bool, reason: str) -> None:
        self.allowed = allowed
        self.reason = reason

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"GrantDecision(allowed={self.allowed}, reason={self.reason!r})"


class GrantService:
    def __init__(self, repo: GrantRepository) -> None:
        self._repo = repo

    # -- human-only lifecycle --------------------------------------------------

    def create_human(
        self,
        *,
        project_id: str,
        name: str,
        scope: ScopeSnapshot,
        risk_caps: frozenset[RiskClass],
        valid_from: datetime,
        valid_to: datetime,
        actor_role: str,
    ) -> EngagementGrant:
        """Create a grant. ``actor_role`` must be "human" (agent DENIED)."""
        self._require_human(actor_role)
        grant = EngagementGrant.create(
            project_id=project_id,
            name=name,
            scope=scope,
            risk_caps=risk_caps,
            valid_from=valid_from,
            valid_to=valid_to,
            created_by=actor_role,
            created_at=utc_now(),
        )
        self._repo.add(grant)
        return grant

    def revoke(self, grant_id: str, *, actor_role: str) -> EngagementGrant:
        """Revoke a grant. ``actor_role`` must be "human" (agent DENIED)."""
        self._require_human(actor_role)
        grant = self._repo.get(grant_id)
        if grant is None:
            raise GrantNotFoundError(f"grant not found: {grant_id}")
        revoked = grant.revoke()
        self._repo.add(revoked)
        return revoked

    # -- pure gate ---------------------------------------------------------------

    def authorize(
        self,
        grant_id: str,
        scope: ScopeSnapshot,
        steps: tuple[PlanStep, ...],
        *,
        now: datetime,
    ) -> GrantDecision:
        """Decide whether the grant authorizes the given scope + plan steps."""
        grant = self._repo.get(grant_id)
        if grant is None:
            return GrantDecision(False, "GRANT_NOT_FOUND")
        if not grant.is_active_at(now):
            return GrantDecision(False, "GRANT_INACTIVE")
        if not grant.covers_scope(scope):
            return GrantDecision(False, "GRANT_SCOPE_MISMATCH")
        if not grant.covers_risks(steps):
            return GrantDecision(False, "GRANT_RISK_NOT_APPROVED")
        return GrantDecision(True, "ALLOWED")

    # -- read surface (agent-discoverable) --------------------------------------

    def list_active(self, project_id: str, *, now: datetime) -> tuple[EngagementGrant, ...]:
        return tuple(
            g for g in self._repo.list_for_project(project_id) if g.is_active_at(now)
        )

    def get_active(self, grant_id: str, *, now: datetime) -> EngagementGrant | None:
        """Fetch a grant ONLY if it exists and is currently active.

        mission_create uses this to validate the grant before building any
        state; a missing/revoked/expired grant returns None (no exception -
        the caller reports the structured denial).
        """
        grant = self._repo.get(grant_id)
        if grant is None or not grant.is_active_at(now):
            return None
        return grant

    # -- internals -----------------------------------------------------------------

    @staticmethod
    def _require_human(actor_role: str) -> None:
        if actor_role != "human":
            raise AssessmentPermissionError(
                "grant creation/revocation is human-only"
            )