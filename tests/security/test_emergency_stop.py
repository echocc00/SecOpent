"""TDD tests for EmergencyStop (M5 Task 5, §12)."""
from __future__ import annotations

from dataclasses import dataclass, field

from secopent.application.audit import AuditService
from secopent.application.emergency_stop import EmergencyStop
from secopent.domain.audit.models import GENESIS_HASH, AuditEvent


@dataclass
class _MemoryAuditRepo:
    events: list[AuditEvent] = field(default_factory=list)

    def add(self, e: AuditEvent) -> None:
        self.events.append(e)

    def list_events(self) -> list[AuditEvent]:
        return list(self.events)

    def last_hash(self) -> str:
        return self.events[-1].event_hash.removeprefix("sha256:") if self.events else GENESIS_HASH


class FakeRevoker:
    def __init__(self, unused: int) -> None:
        self._unused = unused
        self.calls = 0

    def revoke_unused(self) -> int:
        self.calls += 1
        return self._unused


class FakeTerminator:
    def __init__(self, active: int) -> None:
        self._active = active
        self.calls = 0

    def terminate_active(self) -> int:
        self.calls += 1
        return self._active


def _stop(revoker: FakeRevoker, terminator: FakeTerminator, audit: AuditService) -> EmergencyStop:
    return EmergencyStop(
        permit_revoker=revoker, container_terminator=terminator, audit=audit
    )


def test_initially_not_triggered() -> None:
    audit = AuditService(_MemoryAuditRepo())
    stop = _stop(FakeRevoker(0), FakeTerminator(0), audit)
    assert stop.is_triggered is False
    assert stop.permits_allowed() is True


def test_trigger_sets_global_switch_and_blocks_new_permits() -> None:
    audit = AuditService(_MemoryAuditRepo())
    stop = _stop(FakeRevoker(0), FakeTerminator(0), audit)
    stop.trigger(actor="operator", reason="compromise detected")
    assert stop.is_triggered is True
    assert stop.permits_allowed() is False


def test_trigger_revokes_unused_permits() -> None:
    audit = AuditService(_MemoryAuditRepo())
    revoker = FakeRevoker(unused=3)
    stop = _stop(revoker, FakeTerminator(0), audit)
    report = stop.trigger(actor="operator", reason="x")
    assert revoker.calls == 1
    assert report.revoked_permits == 3


def test_trigger_terminates_active_containers() -> None:
    audit = AuditService(_MemoryAuditRepo())
    terminator = FakeTerminator(active=2)
    stop = _stop(FakeRevoker(0), terminator, audit)
    report = stop.trigger(actor="operator", reason="x")
    assert terminator.calls == 1
    assert report.terminated_containers == 2


def test_trigger_preserves_evidence() -> None:
    audit = AuditService(_MemoryAuditRepo())
    stop = _stop(FakeRevoker(0), FakeTerminator(0), audit)
    report = stop.trigger(actor="operator", reason="x")
    assert report.evidence_preserved is True


def test_trigger_writes_high_priority_audit() -> None:
    repo = _MemoryAuditRepo()
    audit = AuditService(repo)
    stop = _stop(FakeRevoker(1), FakeTerminator(1), audit)
    stop.trigger(actor="operator", reason="compromise detected")
    events = [e for e in repo.list_events() if e.action == "emergency_stop.triggered"]
    assert len(events) == 1
    assert events[0].payload["priority"] == "high"
    assert events[0].payload["reason"] == "compromise detected"


def test_trigger_is_idempotent_on_switch() -> None:
    audit = AuditService(_MemoryAuditRepo())
    revoker = FakeRevoker(unused=1)
    stop = _stop(revoker, FakeTerminator(0), audit)
    stop.trigger(actor="operator", reason="x")
    stop.trigger(actor="operator", reason="x")  # second trigger
    assert stop.is_triggered is True  # still triggered, no error
