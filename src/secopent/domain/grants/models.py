"""EngagementGrant: the human-granted authorization boundary (v0.6.0 spec §3.1).

A grant is created ONLY by a human (enforced by GrantService.create_human) and
describes what an agent may autonomously approve/start:

- ``scope``: the exact authorization boundary. It is an embedded
  :class:`ScopeSnapshot` - the SAME model the assessments use - so target
  matching has exactly one implementation (ScopeSnapshot._target_matches,
  fixed by v8 Fix A). Grant creation must never re-implement matching on
  plain include/exclude lists, or the two copies will drift.
- ``risk_caps``: plan risks the grant covers (PASSIVE..INTRUSIVE).
  DESTRUCTIVE is rejected at construction - a destructive action can never
  be grant-approved (the codebase also deny-lists such cases at publish:
  ``domain/cases/risk.py`` returns None for shell/exec/unbounded steps, and
  ``domain/policy/engine.py`` hard-rejects DESTRUCTIVE).
- ``valid_from``/``valid_to``: the window during which the grant is honored.
- ``status``: ACTIVE / REVOKED (state transition only via revoke()).
  Expiry is derived from the window (lazy - is_active_at returns False outside
  the window); persistence may persist EXPIRED opportunistically.

The grant is a signed audit object (its ``digest`` participates in the audit
chain via the caller's audit events carrying ``grant_id``).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum

from ..assessments.models import PlanStep
from ..common.canonical import canonical_digest
from ..common.errors import DomainValidationError
from ..policy.models import RiskClass
from ..scope.models import ScopeSnapshot


class GrantStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class EngagementGrant:
    """Frozen authorization boundary; covers_* are pure predicates."""

    id: str
    project_id: str
    name: str
    scope: ScopeSnapshot  # single source of truth for the authorization boundary
    risk_caps: frozenset[RiskClass]
    valid_from: datetime
    valid_to: datetime
    created_by: str
    created_at: datetime
    status: GrantStatus
    digest: str

    @classmethod
    def create(
        cls,
        *,
        project_id: str,
        name: str,
        scope: ScopeSnapshot,
        risk_caps: frozenset[RiskClass],
        valid_from: datetime,
        valid_to: datetime,
        created_by: str,
        created_at: datetime,
        grant_id: str | None = None,
    ) -> EngagementGrant:
        if not name.strip():
            raise DomainValidationError("grant name must be non-empty")
        if RiskClass.DESTRUCTIVE in risk_caps:
            raise DomainValidationError(
                "destructive risk can never be grant-approved"
            )
        if valid_to <= valid_from:
            raise DomainValidationError("grant window must be positive")
        payload = {
            "project_id": project_id,
            "name": name.strip(),
            "scope_digest": scope.digest,
            "risk_caps": sorted(r.value for r in risk_caps),
            "valid_from": valid_from.isoformat(),
            "valid_to": valid_to.isoformat(),
            "created_by": created_by,
            "created_at": created_at.isoformat(),
        }
        return cls(
            id=grant_id or f"grant-{uuid.uuid4().hex[:12]}",
            project_id=project_id,
            name=name.strip(),
            scope=scope,
            risk_caps=frozenset(risk_caps),
            valid_from=valid_from,
            valid_to=valid_to,
            created_by=created_by,
            created_at=created_at,
            status=GrantStatus.ACTIVE,
            digest=canonical_digest(payload),
        )

    def revoke(self) -> EngagementGrant:
        """Return a copy with status REVOKED (caller persists it)."""
        return replace(self, status=GrantStatus.REVOKED)

    def is_active_at(self, now: datetime) -> bool:
        """Active = not revoked AND within the validity window.

        Expiry is derived (lazy) - the stored ``status`` may still say ACTIVE
        outside the window; callers that persist status may update it to
        EXPIRED opportunistically, but the predicate never lies.
        """
        if self.status is GrantStatus.REVOKED:
            return False
        return not (now < self.valid_from or now > self.valid_to)

    def covers_scope(self, assessment_scope: ScopeSnapshot) -> bool:
        """Every assessment target must match the grant's scope; ports must ⊆."""
        if not set(assessment_scope.ports) <= set(self.scope.ports):
            return False
        return all(
            self._matches_boundary(target) for target in assessment_scope.include
        )

    def covers_risks(self, steps: tuple[PlanStep, ...]) -> bool:
        return all(step.risk in self.risk_caps for step in steps)

    def _matches_boundary(self, target: str) -> bool:
        """Does ``target`` (URL / IP / domain / CIDR) fall inside grant.scope?"""
        try:
            if self.scope.includes_url(target):
                return True
        except DomainValidationError:
            pass
        try:
            if self.scope.includes_ip(target):
                return True
        except DomainValidationError:
            pass
        try:
            return self.scope.includes_domain(target)
        except DomainValidationError:
            return False