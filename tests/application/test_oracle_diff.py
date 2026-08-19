"""TDD integration tests: OracleEngine + DiffSemanticVerifier (v0.7.6, Task 5).

The DIFF_SEMANTIC oracle confirms a logic-level candidate (IDOR etc.) by running
the deterministic diff verifier N times (N/N, default_n=3 for IDOR) through the
unchanged OracleEngine. This test drives a real DiffSemanticVerifier over a
scripted all-success / all-403 runner and asserts the engine aggregates N/N into
CONFIRMED (and promotes via confirm), or REFUTED when the assertion is denied.
"""
from __future__ import annotations

from datetime import UTC, datetime

from secopent.application.audit import AuditService
from secopent.application.canary import CanaryTokenManager
from secopent.application.oracle import OracleEngine
from secopent.domain.verification.diff_semantic import (
    DiffSemanticPayload,
    Expectation,
)
from secopent.domain.verification.models import (
    CandidateFinding,
    ConfirmedFinding,
    VerificationStatus,
    VulnType,
)
from secopent.domain.verification.registry import default_registry
from secopent.infrastructure.oracle.diff_semantic_runner import (
    DiffSemanticResponse,
)
from secopent.infrastructure.oracle.diff_semantic_verifier import (
    DiffSemanticVerifier,
)


class _ScriptedDiffRunner:
    """DiffSemanticRunner that returns canned responses per execute() call.

    A single reproduce() performs exactly two execute() calls (baseline then
    assertion. With N=3 reproductions, the engine drives 6 execute() calls; the
    runner cycles responses so the pattern repeats across reproductions.
    """

    def __init__(
        self,
        baseline: DiffSemanticResponse,
        assertion: DiffSemanticResponse,
    ) -> None:
        self._baseline = baseline
        self._assertion = assertion

    def execute(self, request: dict[str, object]) -> DiffSemanticResponse:
        url = str(request.get("url", ""))
        if url.endswith("/baseline"):
            return self._baseline
        # assertion request -> the suspect override
        return self._assertion


def _candidate(vuln_type: VulnType, diff: DiffSemanticPayload | None) -> CandidateFinding:
    return CandidateFinding(
        id="cand-diff-1",
        observation_id="obs-diff-1",
        vuln_type=vuln_type,
        target="https://x.test/",
        diff=diff,
    )


def _idor_payload() -> DiffSemanticPayload:
    return DiffSemanticPayload(
        candidate_id="cand-diff-1",
        baseline_request={"method": "GET", "url": "/baseline"},
        assertion_request={"method": "GET", "url": "/assertion"},
        expectation=Expectation.DENY,
    )


def _engine(
    baseline: DiffSemanticResponse,
    assertion: DiffSemanticResponse,
    memory_repositories,
) -> OracleEngine:
    audit = AuditService(memory_repositories.audit)
    canary = CanaryTokenManager(audit)
    runner = _ScriptedDiffRunner(baseline, assertion)
    verifier = DiffSemanticVerifier(runner)
    return OracleEngine(registry=default_registry(), verifier=verifier, canary=canary)


def test_verify_confirms_idor_candidate(
    memory_repositories,
) -> None:  # type: ignore[no-untyped-def]
    """Baseline + assertion both 200 same-structure, DENY -> N/N CONFIRMED."""
    engine = _engine(
        DiffSemanticResponse(status=200, body={"id": 1002}),
        DiffSemanticResponse(status=200, body={"id": 1002}),
        memory_repositories,
    )
    result = engine.verify(_candidate(VulnType.IDOR, _idor_payload()), actor="oracle")
    assert result.status is VerificationStatus.CONFIRMED
    assert result.successes == 3 and result.attempts == 3  # N/N (default_n=3)


def test_confirm_promotes(
    memory_repositories,
) -> None:  # type: ignore[no-untyped-def]
    """A CONFIRMED diff result promotes to a ConfirmedFinding."""
    engine = _engine(
        DiffSemanticResponse(status=200, body={"id": 1002}),
        DiffSemanticResponse(status=200, body={"id": 1002}),
        memory_repositories,
    )
    candidate = _candidate(VulnType.IDOR, _idor_payload())
    result = engine.verify(candidate, actor="oracle")
    confirmed = engine.confirm(
        candidate,
        result,
        evidence_ids=(),
        verified_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert isinstance(confirmed, ConfirmedFinding)
    assert confirmed.candidate_id == candidate.id
    assert confirmed.successes == 3 and confirmed.attempts == 3


def test_idor_refuted_when_assertion_denied(
    memory_repositories,
) -> None:  # type: ignore[no-untyped-def]
    """A 403 on the assertion request (defense worked) -> REFUTED at N/N."""
    engine = _engine(
        DiffSemanticResponse(status=200, body={"id": 1002}),
        DiffSemanticResponse(status=403, body=None),
        memory_repositories,
    )
    result = engine.verify(_candidate(VulnType.IDOR, _idor_payload()), actor="oracle")
    assert result.status is VerificationStatus.REFUTED
    assert result.successes == 0
