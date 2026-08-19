# tests/infrastructure/test_diff_semantic_verifier.py
"""TDD tests for DiffSemanticVerifier (v0.7.6, Task 4).

The DIFF_SEMANTIC verifier is a legal OracleVerifier implementation: it reads the
diff spec from candidate.diff, drives the runner (baseline->A, assertion->B),
computes the AssertionResult inputs (refused / structure_same / state_ok), and
DELEGATES the verdict to the already-correct decide_diff_outcome (Task 2). The
verifier itself decides nothing.

These tests use a scripted runner fake (duck-typed). The verifier must handle a
runner WITHOUT with_session (via hasattr detection) as well as one WITH it.
"""
from __future__ import annotations

from typing import Any

from secopent.domain.verification.diff_semantic import (
    DiffSemanticPayload,
    Expectation,
)
from secopent.domain.verification.models import (
    CandidateFinding,
    ReproductionStatus,
    VerificationMethod,
    VulnType,
)
from secopent.infrastructure.oracle.diff_semantic_runner import (
    DiffSemanticResponse,
)
from secopent.infrastructure.oracle.diff_semantic_verifier import (
    DiffSemanticVerifier,
)

_METHOD = VerificationMethod(
    vuln_type=VulnType.IDOR,
    default_n=1,
    diff_semantic=True,
)


class _ScriptedRunner:
    """Duck-typed DiffSemanticRunner with NO with_session (minimal fake).

    Pops a canned DiffSemanticResponse per execute() call. The verifier must use
    this runner directly because it has no with_session capability.
    """

    def __init__(self, responses: list[DiffSemanticResponse]) -> None:
        self._responses = responses
        self.requests: list[dict[str, object]] = []
        self.session_used: object | None = None

    def execute(self, request: dict[str, object]) -> DiffSemanticResponse:
        self.requests.append(request)
        return self._responses.pop(0)


class _SessionedRunner(_ScriptedRunner):
    """Scripted runner that ALSO implements with_session (real-runner shape)."""

    def with_session(self, session: object) -> _SessionedRunner:
        self.session_used = session
        return self


def _candidate(diff: object | None) -> CandidateFinding:
    return CandidateFinding(
        id="c-1",
        observation_id="obs-1",
        vuln_type=VulnType.IDOR,
        target="http://target",
        diff=diff,
    )


def _payload(**kw: Any) -> DiffSemanticPayload:
    base = {
        "candidate_id": "c-1",
        "baseline_request": {"method": "GET", "url": "/a"},
        "assertion_request": {"method": "GET", "url": "/b"},
        "expectation": Expectation.DENY,
    }
    base.update(kw)
    return DiffSemanticPayload(**base)


def test_idor_confirmed_when_B_200_same_struct() -> None:
    diff = _payload(expectation=Expectation.DENY)
    runner = _ScriptedRunner(
        [
            DiffSemanticResponse(status=200, body={"id": 1002}),
            DiffSemanticResponse(status=200, body={"id": 1002}),
        ]
    )
    verifier = DiffSemanticVerifier(runner)

    status = verifier.reproduce(
        _candidate(diff), _METHOD, canary_token="tok"
    )

    assert status is ReproductionStatus.SUCCESS
    # baseline /a then assertion /b in order.
    assert [r.get("url") for r in runner.requests] == ["/a", "/b"]


def test_idor_refuted_when_B_403() -> None:
    diff = _payload(expectation=Expectation.DENY)
    runner = _ScriptedRunner(
        [
            DiffSemanticResponse(status=200, body={"id": 1002}),
            DiffSemanticResponse(status=403, body=None),
        ]
    )
    verifier = DiffSemanticVerifier(runner)

    status = verifier.reproduce(_candidate(diff), _METHOD, canary_token="tok")

    assert status is ReproductionStatus.FAILURE


def test_no_diff_spec_is_failure() -> None:
    runner = _ScriptedRunner([])
    verifier = DiffSemanticVerifier(runner)

    status = verifier.reproduce(_candidate(None), _METHOD, canary_token="tok")

    # Clear FAILURE (not silently routed to a wrong confirm channel), and the
    # runner must never be called for a missing spec.
    assert status is ReproductionStatus.FAILURE
    assert runner.requests == []


def test_transport_error_serr() -> None:
    diff = _payload(expectation=Expectation.DENY)
    runner = _ScriptedRunner(
        [
            DiffSemanticResponse(status=200, body={"id": 1002}),
            DiffSemanticResponse(status=0, error="boom"),
        ]
    )
    verifier = DiffSemanticVerifier(runner)

    status = verifier.reproduce(_candidate(diff), _METHOD, canary_token="tok")

    assert status is ReproductionStatus.SERVER_ERROR


def test_state_readback_refutes_single_spend() -> None:
    # SINGLE_SPEND with a state_readback URL; the readback body differs from the
    # conservative expectation -> _readback_ok yields False -> FAILURE (Task 2
    # treats state_ok=False as FAILURE for SINGLE_SPEND).
    diff = _payload(
        expectation=Expectation.SINGLE_SPEND,
        state_readback="/balance",
    )
    runner = _ScriptedRunner(
        [
            DiffSemanticResponse(status=200, body={"id": 1002}),
            DiffSemanticResponse(status=200, body={"id": 1002}),
            # Readback body differs from the conservative expected state.
            DiffSemanticResponse(status=200, body={"spent": 1}),
        ]
    )
    verifier = DiffSemanticVerifier(runner)

    status = verifier.reproduce(_candidate(diff), _METHOD, canary_token="tok")

    assert status is ReproductionStatus.FAILURE
    # Third request was the readback.
    assert len(runner.requests) == 3
    assert runner.requests[2]["url"] == "/balance"


def test_state_readback_ok_single_spend_success() -> None:
    diff = _payload(
        expectation=Expectation.SINGLE_SPEND,
        state_readback="/balance",
    )
    runner = _ScriptedRunner(
        [
            DiffSemanticResponse(status=200, body={"id": 1002}),
            DiffSemanticResponse(status=200, body={"id": 1002}),
            # Readback matches the conservative expected (empty) state.
            DiffSemanticResponse(status=200, body={}),
        ]
    )
    verifier = DiffSemanticVerifier(runner)

    status = verifier.reproduce(_candidate(diff), _METHOD, canary_token="tok")

    assert status is ReproductionStatus.SUCCESS


def test_state_readback_transport_error_serr() -> None:
    diff = _payload(
        expectation=Expectation.SINGLE_SPEND,
        state_readback="/balance",
    )
    runner = _ScriptedRunner(
        [
            DiffSemanticResponse(status=200, body={"id": 1002}),
            DiffSemanticResponse(status=200, body={"id": 1002}),
            DiffSemanticResponse(status=0, error="boom"),
        ]
    )
    verifier = DiffSemanticVerifier(runner)

    status = verifier.reproduce(_candidate(diff), _METHOD, canary_token="tok")

    assert status is ReproductionStatus.SERVER_ERROR


def test_with_session_used_when_runner_has_it() -> None:
    diff = _payload()
    runner = _SessionedRunner(
        [
            DiffSemanticResponse(status=200, body={"id": 1002}),
            DiffSemanticResponse(status=200, body={"id": 1002}),
        ]
    )
    session = object()
    verifier = DiffSemanticVerifier(runner)

    status = verifier.reproduce(
        _candidate(diff), _METHOD, canary_token="tok", session=session
    )

    assert status is ReproductionStatus.SUCCESS
    assert runner.session_used is session


def test_no_session_uses_runner_directly() -> None:
    diff = _payload()
    runner = _SessionedRunner(
        [
            DiffSemanticResponse(status=200, body={"id": 1002}),
            DiffSemanticResponse(status=200, body={"id": 1002}),
        ]
    )
    verifier = DiffSemanticVerifier(runner)

    status = verifier.reproduce(_candidate(diff), _METHOD, canary_token="tok")

    assert status is ReproductionStatus.SUCCESS
    assert runner.session_used is None
