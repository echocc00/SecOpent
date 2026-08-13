from __future__ import annotations

import uuid
from dataclasses import dataclass

from ..domain.scope.models import ScopeDraft, ScopeLimits, ScopeSnapshot
from ..domain.scope.normalize import normalize_cloud_account, normalize_port
from .audit import AuditService
from .ports.repositories import ScopeRepository


@dataclass(frozen=True, slots=True)
class ScopeValidationResult:
    """Deterministic, side-effect-free result of ``ScopeService.validate``.

    ``include``/``exclude``/``ports``/``cloud_accounts`` carry the normalized
    values (empty on an invalid draft); ``errors`` is a tuple of
    ``(field, index, raw, error)`` rows for every target that failed to
    normalize. ``ok`` is True iff there are no errors.
    """

    include: tuple[str, ...]
    exclude: tuple[str, ...]
    ports: tuple[int, ...]
    cloud_accounts: tuple[str, ...]
    errors: tuple[tuple[str, int, str, str], ...]

    @property
    def ok(self) -> bool:
        return not self.errors


class ScopeService:
    def __init__(self, repo: ScopeRepository, audit: AuditService) -> None:
        self._repo = repo
        self._audit = audit

    def validate(
        self,
        *,
        include: tuple[str, ...],
        exclude: tuple[str, ...] = (),
        ports: tuple[int, ...] = (443,),
        cloud_accounts: tuple[str, ...] = (),
    ) -> ScopeValidationResult:
        """Normalize a scope draft WITHOUT persisting it (MCP scope_validate).

        Every include/exclude target and cloud account is normalized using the
        same helpers ``ScopeDraft.freeze`` uses; a target that fails to
        normalize is reported as an ``(field, index, raw, error)`` row instead
        of raising, so the caller can fix the draft before ``freeze``. Never
        raises on a bad target (the tool contract is "report problems").
        """
        norm_include: list[str] = []
        norm_exclude: list[str] = []
        norm_accounts: list[str] = []
        errors: list[tuple[str, int, str, str]] = []
        bad_port_indices: set[int] = set()

        def _row(field: str, index: int, raw: str, exc: BaseException) -> None:
            errors.append((field, index, raw, str(exc)))

        for i, raw in enumerate(include):
            try:
                norm_include.append(ScopeDraft._normalize_target(raw))
            except Exception as exc:  # noqa: BLE001 - report any normalize failure
                _row("include", i, raw, exc)
        for i, raw in enumerate(exclude):
            try:
                norm_exclude.append(ScopeDraft._normalize_target(raw))
            except Exception as exc:  # noqa: BLE001 - report any normalize failure
                _row("exclude", i, raw, exc)
        for i, port in enumerate(ports):
            try:
                normalize_port(port)
            except Exception as exc:  # noqa: BLE001 - report any normalize failure
                bad_port_indices.add(i)
                _row("ports", i, str(port), exc)
        for i, raw in enumerate(cloud_accounts):
            try:
                norm_accounts.append(normalize_cloud_account(raw))
            except Exception as exc:  # noqa: BLE001 - report any normalize failure
                _row("cloud_accounts", i, raw, exc)

        valid_ports = tuple(sorted({p for i, p in enumerate(ports) if i not in bad_port_indices}))
        return ScopeValidationResult(
            include=tuple(sorted(set(norm_include))),
            exclude=tuple(sorted(set(norm_exclude))),
            ports=valid_ports,
            cloud_accounts=tuple(sorted(set(norm_accounts))),
            errors=tuple(errors),
        )

    def freeze(self, *, project_id: str, include: tuple[str, ...],
               exclude: tuple[str, ...] = (), ports: tuple[int, ...] = (443,),
               approved_by: str,
               requests_per_second: float = 5.0,
               concurrency: int = 3,
               max_requests: int = 50_000,
               cloud_accounts: tuple[str, ...] = ()) -> ScopeSnapshot:
        limits = ScopeLimits(
            requests_per_second=requests_per_second,
            concurrency=concurrency,
            max_requests=max_requests,
        )
        draft = ScopeDraft(
            project_id=project_id, include=include, exclude=exclude,
            ports=ports, limits=limits, cloud_accounts=cloud_accounts,
        )
        snapshot = draft.freeze(
            snapshot_id=f"scope-{uuid.uuid4().hex[:12]}",
            approved_by=approved_by,
        )
        self._repo.add_snapshot(snapshot)
        self._audit.record(
            actor=approved_by, action="scope.frozen",
            resource_type="scope_snapshot", resource_id=snapshot.id,
            payload={"project_id": project_id, "digest": snapshot.digest},
        )
        return snapshot
