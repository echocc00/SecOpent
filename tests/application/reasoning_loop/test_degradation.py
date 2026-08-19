# tests/application/reasoning_loop/test_degradation.py
"""DegradationPolicy — real→mock→catalog degradation chain, all audited.

v0.7.3 Task 3. The policy turns a failure streak (repeated schema fail /
backend-unavailable) into an explicit ``DegradeAction`` and ALWAYS audits the
degradation via ``loop.fallback_used`` (never silent, spec §10).

The catalog-only floor is enforced upstream by the Assessment gate
(CoverageService), which refuses to propose when only the catalog remains —
this policy returns ``CATALOG_ONLY``; it does not inject messages.
"""
from __future__ import annotations

from secopent.application.ports.audit import AuditRecorder
from secopent.application.reasoning_loop.audit import LOOP_FALLBACK_USED
from secopent.application.reasoning_loop.degradation import (
    BackendState,
    DegradationPolicy,
    DegradeAction,
)


class FakeAuditRecorder:
    """Records audit calls as (payload, kwargs) tuples for assertions."""

    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def record(
        self,
        *,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str,
        payload: dict[str, object],
        session: object = None,
    ) -> object:
        self.events.append(
            {
                "actor": actor,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "payload": payload,
            }
        )
        return None


def _recorder() -> tuple[AuditRecorder, FakeAuditRecorder]:
    fake = FakeAuditRecorder()
    return fake, fake  # type: ignore[return-value]


class TestEvaluateDecisionTable:
    def test_low_streak_backend_available_proposes_again(self) -> None:
        p = DegradationPolicy()
        assert (
            p.evaluate(failure_streak=2, backend_state=BackendState.AVAILABLE)
            is DegradeAction.PROPOSE_AGAIN
        )

    def test_zero_streak_proposes_again(self) -> None:
        p = DegradationPolicy()
        assert (
            p.evaluate(failure_streak=0, backend_state=BackendState.AVAILABLE)
            is DegradeAction.PROPOSE_AGAIN
        )

    def test_streak_at_threshold_blocks_policy(self) -> None:
        p = DegradationPolicy()
        assert (
            p.evaluate(failure_streak=3, backend_state=BackendState.AVAILABLE)
            is DegradeAction.POLICY_BLOCKED
        )

    def test_streak_over_threshold_blocks_policy(self) -> None:
        p = DegradationPolicy()
        assert (
            p.evaluate(failure_streak=8, backend_state=BackendState.AVAILABLE)
            is DegradeAction.POLICY_BLOCKED
        )

    def test_unavailable_degrades_to_mock_immediately(self) -> None:
        p = DegradationPolicy()
        assert (
            p.evaluate(failure_streak=0, backend_state=BackendState.UNAVAILABLE)
            is DegradeAction.USE_MOCK
        )

    def test_unavailable_beats_low_streak(self) -> None:
        p = DegradationPolicy()
        assert (
            p.evaluate(failure_streak=2, backend_state=BackendState.UNAVAILABLE)
            is DegradeAction.USE_MOCK
        )

    def test_unavailable_beats_streak_block(self) -> None:
        # Backend down is immediate mock fallback, wins over the streak cap.
        p = DegradationPolicy()
        assert (
            p.evaluate(failure_streak=9, backend_state=BackendState.UNAVAILABLE)
            is DegradeAction.USE_MOCK
        )

    def test_catalog_only_terminates_loop(self) -> None:
        p = DegradationPolicy()
        assert (
            p.evaluate(
                failure_streak=3, backend_state=BackendState.CATALOG_ONLY
            )
            is DegradeAction.CATALOG_ONLY
        )


class TestAuditRecording:
    def test_blocked_streak_is_audited(self) -> None:
        audit, fake = _recorder()
        DegradationPolicy().record_fallback(
            audit,
            reason="schema fails: 3 consecutive retryable outcomes",
            degraded_to=DegradeAction.POLICY_BLOCKED,
        )
        assert len(fake.events) == 1
        ev = fake.events[0]
        assert ev["action"] == LOOP_FALLBACK_USED
        assert ev["actor"] == "reasoning_loop"
        assert ev["resource_type"] == "reasoning_loop"
        assert "reason" in ev["payload"]
        assert ev["payload"]["degraded_to"] == DegradeAction.POLICY_BLOCKED.value

    def test_mock_backend_degration_is_audited(self) -> None:
        audit, fake = _recorder()
        DegradationPolicy().record_fallback(
            audit,
            reason="LLM backend unavailable",
            degraded_to=DegradeAction.USE_MOCK,
        )
        assert len(fake.events) == 1
        assert fake.events[0]["action"] == LOOP_FALLBACK_USED

    def test_catalog_only_degration_is_audited(self) -> None:
        audit, fake = _recorder()
        DegradationPolicy().record_fallback(
            audit,
            reason="only catalog remains; loop cannot propose",
            degraded_to=DegradeAction.CATALOG_ONLY,
        )
        assert len(fake.events) == 1
        assert fake.events[0]["action"] == LOOP_FALLBACK_USED

    def test_audit_payload_carries_reason(self) -> None:
        audit, fake = _recorder()
        reason = "no LLM key configured"
        DegradationPolicy().record_fallback(
            audit, reason=reason, degraded_to=DegradeAction.USE_MOCK
        )
        assert fake.events[0]["payload"]["reason"] == reason


class TestCatalogOnlyTerminatesLoop:
    def test_catalog_only_does_not_produce_a_message(self) -> None:
        # The Assessment gate (CoverageService) blocks proposals downstream; a
        # DegradationPolicy returning CATALOG_ONLY must NOT fabricate an action/
        # message. Assert the action is a terminal signal, not a ProposeAction.
        p = DegradationPolicy()
        action = p.evaluate(
            failure_streak=3, backend_state=BackendState.CATALOG_ONLY
        )
        assert action is DegradeAction.CATALOG_ONLY