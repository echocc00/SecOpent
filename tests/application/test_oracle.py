"""TDD tests for OracleEngine (M2 Task 2, §9 / ADR-004: N/N, not LLM).

The OracleEngine verifies a CandidateFinding by running N independent
reproductions through an injected verifier (the pentest-ai adapter in
production, a scripted fake in tests) and aggregating the results with the
deterministic ``decide_outcome`` rule. A finding is CONFIRMED only at N/N
successes; server errors (5xx) count as INCONCLUSIVE, never REFUTED. The LLM is
never in the confirmation path - only the oracle decides.
"""
from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

import pytest

from secopent.application.audit import AuditService
from secopent.application.canary import CanaryTokenManager
from secopent.application.oracle import OracleEngine, OracleVerifier
from secopent.domain.common.errors import DomainValidationError
from secopent.domain.verification.models import (
    CandidateFinding,
    ConfirmedFinding,
    ReproductionStatus,
    VerificationMethod,
    VerificationStatus,
    VulnType,
)
from secopent.domain.verification.registry import default_registry


class ScriptedVerifier:
    """Fake oracle backend returning a scripted status per reproduction."""

    def __init__(self, outcomes: Sequence[ReproductionStatus]) -> None:
        self._outcomes = list(outcomes)
        self.calls: list[tuple[str, str]] = []  # (target, canary_token)

    def reproduce(
        self,
        candidate: CandidateFinding,
        method: VerificationMethod,
        *,
        canary_token: str,
    ) -> ReproductionStatus:
        self.calls.append((candidate.target, canary_token))
        if self._outcomes:
            return self._outcomes.pop(0)
        return ReproductionStatus.FAILURE


@pytest.fixture
def engine_factory(memory_repositories):  # type: ignore[no-untyped-def]
    audit = AuditService(memory_repositories.audit)
    canary = CanaryTokenManager(audit)
    registry = default_registry()

    def _make(verifier: OracleVerifier) -> OracleEngine:
        return OracleEngine(registry=registry, verifier=verifier, canary=canary)

    return _make


def _candidate(vuln_type: VulnType) -> CandidateFinding:
    return CandidateFinding(
        id="cand-1",
        observation_id="obs-1",
        vuln_type=vuln_type,
        target="https://x.test/",
    )


# --- W2-C T5: OracleEngine + RescanVerifier(canary=...) end-to-end ---------


class _EchoRunner:
    """Fake RealScanRunner that echoes the scan args back in stdout.

    Simulates a target that reflects the canary token embedded in the probe,
    so verify_echo can detect it. ``echo`` toggles whether the token comes back.
    """

    def __init__(self, *, echo: bool = True) -> None:
        self._echo = echo

    def scan(self, adapter_key: str, *, args: Sequence[str], **kwargs: object) -> object:
        class _Result:
            pass

        r = _Result()
        r.observations = ()  # type: ignore[attr-defined]
        r.stdout = " ".join(args) if self._echo else "no canary here"  # type: ignore[attr-defined]
        return r


def test_oracle_with_canary_rescan_verifier_confirms_on_echo(
    memory_repositories,  # type: ignore[no-untyped-def]
) -> None:
    """W2-C T5: a real RescanVerifier with canary injected + a placeholder in
    the scan kwargs -> N/N echoes -> CONFIRMED."""
    from secopent.application.canary import CANARY_PLACEHOLDER
    from secopent.infrastructure.oracle.rescan_verifier import RescanVerifier

    audit = AuditService(memory_repositories.audit)
    canary = CanaryTokenManager(audit)
    verifier = RescanVerifier(
        runner=_EchoRunner(echo=True),  # type: ignore[arg-type]
        scan_kwargs={"adapter_key": "nuclei", "args": ["-u", f"http://t/{CANARY_PLACEHOLDER}"]},
        canary=canary,
    )
    engine = OracleEngine(registry=default_registry(), verifier=verifier, canary=canary)

    result = engine.verify(_candidate(VulnType.SQLI), actor="oracle")
    assert result.status is VerificationStatus.CONFIRMED
    assert result.successes == result.attempts  # N/N


def test_oracle_with_canary_rescan_verifier_not_confirmed_without_echo(
    memory_repositories,  # type: ignore[no-untyped-def]
) -> None:
    """W2-C T5: no canary echo in stdout -> not CONFIRMED (REFUTED)."""
    from secopent.application.canary import CANARY_PLACEHOLDER
    from secopent.infrastructure.oracle.rescan_verifier import RescanVerifier

    audit = AuditService(memory_repositories.audit)
    canary = CanaryTokenManager(audit)
    verifier = RescanVerifier(
        runner=_EchoRunner(echo=False),  # type: ignore[arg-type]
        scan_kwargs={"adapter_key": "nuclei", "args": ["-u", f"http://t/{CANARY_PLACEHOLDER}"]},
        canary=canary,
    )
    engine = OracleEngine(registry=default_registry(), verifier=verifier, canary=canary)

    result = engine.verify(_candidate(VulnType.SQLI), actor="oracle")
    assert result.status is not VerificationStatus.CONFIRMED
    assert result.successes == 0


def test_confirmed_at_n_of_n_successes(engine_factory) -> None:  # type: ignore[no-untyped-def]
    # RCE needs N=3.
    verifier = ScriptedVerifier([ReproductionStatus.SUCCESS] * 3)
    engine = engine_factory(verifier)
    result = engine.verify(_candidate(VulnType.RCE), actor="oracle")
    assert result.status is VerificationStatus.CONFIRMED
    assert result.successes == 3
    assert result.attempts == 3


def test_sqli_needs_five_reproductions(engine_factory) -> None:  # type: ignore[no-untyped-def]
    verifier = ScriptedVerifier([ReproductionStatus.SUCCESS] * 5)
    engine = engine_factory(verifier)
    result = engine.verify(_candidate(VulnType.SQLI), actor="oracle")
    assert result.status is VerificationStatus.CONFIRMED
    assert result.successes == 5


def test_refuted_when_reproductions_fail(engine_factory) -> None:  # type: ignore[no-untyped-def]
    verifier = ScriptedVerifier([ReproductionStatus.FAILURE] * 3)
    engine = engine_factory(verifier)
    result = engine.verify(_candidate(VulnType.RCE), actor="oracle")
    assert result.status is VerificationStatus.REFUTED
    assert result.successes == 0


def test_server_errors_yield_inconclusive_not_refuted(engine_factory) -> None:  # type: ignore[no-untyped-def]
    # 1 success + 2 server errors (>= threshold 2) -> INCONCLUSIVE, not REFUTED.
    verifier = ScriptedVerifier(
        [
            ReproductionStatus.SUCCESS,
            ReproductionStatus.SERVER_ERROR,
            ReproductionStatus.SERVER_ERROR,
        ]
    )
    engine = engine_factory(verifier)
    result = engine.verify(_candidate(VulnType.RCE), actor="oracle")
    assert result.status is VerificationStatus.INCONCLUSIVE


def test_one_server_error_below_threshold_is_refuted(engine_factory) -> None:  # type: ignore[no-untyped-def]
    # 0 success + 1 server error + 1 failure; inconclusive(1) < threshold(2) -> REFUTED.
    verifier = ScriptedVerifier(
        [ReproductionStatus.SERVER_ERROR, ReproductionStatus.FAILURE, ReproductionStatus.FAILURE]
    )
    engine = engine_factory(verifier)
    result = engine.verify(_candidate(VulnType.RCE), actor="oracle")
    assert result.status is VerificationStatus.REFUTED


def test_each_reproduction_gets_a_fresh_canary_token(engine_factory) -> None:  # type: ignore[no-untyped-def]
    verifier = ScriptedVerifier([ReproductionStatus.SUCCESS] * 3)
    engine = engine_factory(verifier)
    engine.verify(_candidate(VulnType.RCE), actor="oracle")
    tokens = [token for _, token in verifier.calls]
    assert len(tokens) == 3
    assert len(set(tokens)) == 3, "each reproduction must use a unique canary token"


def test_confirm_builds_confirmed_finding_when_confirmed(engine_factory) -> None:  # type: ignore[no-untyped-def]
    verifier = ScriptedVerifier([ReproductionStatus.SUCCESS] * 3)
    engine = engine_factory(verifier)
    candidate = _candidate(VulnType.RCE)
    result = engine.verify(candidate, actor="oracle")
    confirmed = engine.confirm(
        candidate, result, evidence_ids=("ev-1",), verified_at=datetime(2026, 1, 1, tzinfo=UTC)
    )
    assert isinstance(confirmed, ConfirmedFinding)
    assert confirmed.candidate_id == candidate.id
    assert confirmed.successes == 3


def test_confirm_rejects_non_confirmed_result(engine_factory) -> None:  # type: ignore[no-untyped-def]
    verifier = ScriptedVerifier([ReproductionStatus.FAILURE] * 3)
    engine = engine_factory(verifier)
    candidate = _candidate(VulnType.RCE)
    result = engine.verify(candidate, actor="oracle")
    with pytest.raises(DomainValidationError):
        engine.confirm(
            candidate, result, evidence_ids=(), verified_at=datetime(2026, 1, 1, tzinfo=UTC)
        )


def test_unknown_vuln_type_raises(memory_repositories) -> None:  # type: ignore[no-untyped-def]
    from secopent.domain.verification.registry import VerificationMethodRegistry

    audit = AuditService(memory_repositories.audit)
    # An empty registry has no method for RCE -> require_method raises.
    engine = OracleEngine(
        registry=VerificationMethodRegistry([]),
        verifier=ScriptedVerifier([]),
        canary=CanaryTokenManager(audit),
    )
    with pytest.raises(DomainValidationError):
        engine.verify(_candidate(VulnType.RCE), actor="oracle")
