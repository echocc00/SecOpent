from __future__ import annotations

from typing import Protocol

from ...domain.assessments.models import Approval, Assessment, ExecutionPlan
from ...domain.audit.models import AuditEvent
from ...domain.peer_agents.models import PeerAgentRun
from ...domain.projects.models import Project
from ...domain.scope.models import ScopeSnapshot
from ...domain.updates.models import UpdateBundle


class ProjectRepository(Protocol):
    def add(self, project: Project) -> None: ...
    def get(self, project_id: str) -> Project | None: ...


class ScopeRepository(Protocol):
    def add_snapshot(self, snapshot: ScopeSnapshot) -> None: ...
    def get_snapshot(self, snapshot_id: str) -> ScopeSnapshot | None: ...


class AssessmentRepository(Protocol):
    def add(self, assessment: Assessment) -> None: ...
    def get(self, assessment_id: str) -> Assessment | None: ...
    def save_plan(self, plan: ExecutionPlan) -> None: ...
    def get_plan(self, plan_id: str) -> ExecutionPlan | None: ...
    def save_approval(self, approval: Approval) -> None: ...
    def get_approval(self, approval_id: str) -> Approval | None: ...


class AuditRepository(Protocol):
    def add(self, event: AuditEvent) -> None: ...
    def list_events(self) -> list[AuditEvent]: ...
    def last_hash(self) -> str:
        """Return the bare 64-hex hash (no ``sha256:`` prefix) of the most recent event,
        or the all-zero genesis hash when the audit log is empty. The returned value
        is suitable for direct use as ``AuditEvent.previous_hash``."""
        ...


class BundleFetcher(Protocol):
    """Download port for Update Bundle acquisition (§10.3).

    Returns the raw bundle bytes and detached Ed25519 signature bytes.
    Implementations live in infrastructure (httpx-based online fetcher,
    file-based offline importer). Tests inject a fake.
    """

    def fetch(self, source: str) -> tuple[bytes, bytes]:
        """Return ``(bundle_bytes, signature_bytes)`` for the given source URI."""
        ...


class SignatureVerifier(Protocol):
    """Verify an Update Bundle signature (§10.4).

    Abstracted behind a Protocol so the application layer stays free of
    ``cryptography`` (Ed25519 is implemented in
    ``infrastructure/signing/ed25519.py`` and registered at composition
    root).
    """

    def verify(
        self, bundle: UpdateBundle, signature: bytes, public_key: bytes
    ) -> bool:
        """Return True iff ``signature`` over ``bundle`` is valid for ``public_key``."""
        ...


class BundleRepository(Protocol):
    """Staging + atomic-activation port for Update Bundles.

    Mirrors the M1 Task 4 ORM pattern: ``CoreUpdateBundle`` rows retain
    every staged bundle (old snapshots are NOT deleted on activation,
    enabling ``rollback()``), and ``CoreBundleActivation`` is the
    single-row active-pointer table whose update is the atomic switch.
    """

    def stage(self, bundle: UpdateBundle, signature: bytes) -> None:
        """Persist a staged bundle. Staging never overwrites the active pointer."""
        ...

    def get_staged(self, bundle_id: str) -> object | None:
        """Return the staged row for ``bundle_id`` or None. The returned
        object exposes ``bundle_id``, ``version``, ``digest``, ``payload``,
        and ``signature`` attributes."""
        ...

    def list_staged(self) -> list[object]:
        """Return all staged bundles (active + retained history)."""
        ...

    def activate(self, bundle_id: str) -> str:
        """Atomically swap the single-row activation pointer to ``bundle_id``.

        Implementations MUST retain the previous active id so ``rollback()``
        can restore it. Returns the newly activated bundle id.
        """
        ...

    def get_active_bundle_id(self) -> str | None:
        """Return the currently active bundle id, or None if nothing has
        been activated yet."""
        ...

    def get_previous_bundle_id(self) -> str | None:
        """Return the bundle id that was active before the current one, or
        None if there is no previous bundle to roll back to."""
        ...

    def rollback_to_previous(self) -> str | None:
        """Atomically restore the previous active bundle id. Returns the
        restored (now-active) bundle id. Raises if no previous exists."""
        ...


class PeerRunRepository(Protocol):
    """Persistence port for peer agent runs (P0 ships the in-memory impl;
    the SQLite table lands with P2 wiring)."""

    def add(self, run: PeerAgentRun) -> None: ...
    def save(self, run: PeerAgentRun) -> None: ...  # upsert (status updates)
    def get(self, run_id: str) -> PeerAgentRun | None: ...
    def list_for_assessment(
        self, assessment_id: str
    ) -> tuple[PeerAgentRun, ...]: ...
