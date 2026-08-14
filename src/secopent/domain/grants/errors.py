"""Grant authorization errors (v0.6.0 spec §3.1 / §3.3).

Distinct errors let the approval gate (and MCP handlers) tell the caller WHY
a grant could not authorize an assessment - a refused scan must be diagnosable.
"""
from __future__ import annotations

from ..common.errors import DomainError


class GrantNotFoundError(DomainError):
    """No grant with the given id (or it does not match the caller's view)."""


class GrantInactiveError(DomainError):
    """The grant is revoked or outside its validity window."""


class GrantScopeMismatchError(DomainError):
    """The assessment's targets/ports are not covered by the grant's scope."""


class GrantRiskNotApprovedError(DomainError):
    """A plan step's risk exceeds the grant's risk caps."""