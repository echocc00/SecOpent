# src/secopent/infrastructure/oracle/diff_semantic_verifier.py
"""DiffSemanticVerifier: OracleVerifier impl for DIFF_SEMANTIC (v0.7.6, Task 4).

The DIFF_SEMANTIC verifier is a *legal* OracleVerifier implementation. It does
NOT re-derive semantics — it only wires the transport output into the decision
inputs. It reads the diff spec from ``candidate.diff``, drives the runner
(baseline -> A, assertion -> B, optional state readback), computes the
``AssertionResult`` fields (``refused`` / ``structure_same`` / ``state_ok``), and
delegates the verdict to the already-correct ``decide_diff_outcome`` (Task 2).

The verifier DECIDES NOTHING itself. Any wrong-looking body, refused response,
or transport failure is turned into the corresponding AssertionResult field and
the domain rule makes the call. This keeps a single source of truth for the
differential semantics.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from secopent.domain.verification.diff_semantic import (
    AssertionResult,
    DiffResponse,
    DiffSemanticPayload,
    decide_diff_outcome,
)
from secopent.domain.verification.models import ReproductionStatus

from .diff_semantic_runner import DiffSemanticResponse, DiffSemanticRunner

if TYPE_CHECKING:
    from secopent.application.oracle import OracleVerifier  # noqa: F401
    from secopent.domain.verification.models import CandidateFinding, VerificationMethod


def _structure_compatible(a: object | None, b: object | None) -> bool:
    """Recursive structural comparison of dict/list/leaf (type-of equality).

    None/None -> True; one None -> False; dict: same keys + recursive values;
    list: same length + recursive; else ``type(a) is type(b)``.
    """
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    if isinstance(a, dict) and isinstance(b, dict):
        if a.keys() != b.keys():
            return False
        return all(_structure_compatible(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return False
        return all(_structure_compatible(x, y) for x, y in zip(a, b, strict=False))
    return type(a) is type(b)


def _readback_ok(diff: DiffSemanticPayload, state: DiffSemanticResponse) -> bool:
    """Conservative predicate on a single-spend state readback.

    A single-spend expectation asserts the suspect override happens at most once.
    The readback runs after the assertion to check the object's state. We are
    conservative toward REFUTING: a readback whose body is empty (no detectable
    residue / unchanged state) is ``ok``; a non-empty body signals some state
    effect we cannot rule out as a double-spend, so it is NOT ``ok`` (yields
    ``state_ok=False`` -> FAILURE via decide_diff_outcome).

    TODO(v0.7.7-later): a richer predicate could diff the readback against the
    baseline/assertion request bodies or an expected-state schema. Keeping it
    simple + documented here; the domain rule remains authoritative.
    """
    return not bool(state.body)


class DiffSemanticVerifier:
    """Deterministic differential-semantics verification of a candidate finding.

    Implements the :class:`OracleVerifier` Protocol. ``runner`` is a
    :class:`DiffSemanticRunner` transport. The optional ``with_session``
    capability is detected via ``hasattr`` (the Protocol declares it optional, so
    a minimal fake may omit it); when present and a ``session`` is passed, the
    verifier uses ``runner.with_session(session)``, otherwise ``runner`` itself.
    """

    __slots__ = ("_runner",)

    def __init__(self, runner: DiffSemanticRunner) -> None:
        self._runner = runner

    def reproduce(
        self,
        candidate: CandidateFinding,
        method: VerificationMethod,
        *,
        canary_token: str,
        session: object | None = None,
    ) -> ReproductionStatus:
        diff = candidate.diff
        if not isinstance(diff, DiffSemanticPayload):
            return ReproductionStatus.FAILURE

        runner = self._runner
        if session is not None and hasattr(self._runner, "with_session"):
            runner = self._runner.with_session(session)

        base = runner.execute(diff.baseline_request)
        assertion = runner.execute(diff.assertion_request)
        if base.status == 0 or assertion.status == 0:
            return ReproductionStatus.SERVER_ERROR

        refused = assertion.status in (400, 401, 403)
        structure_same = _structure_compatible(base.body, assertion.body)
        state_ok: bool | None = None
        if diff.state_readback:
            state = runner.execute({"method": "GET", "url": diff.state_readback})
            if state.status == 0:
                return ReproductionStatus.SERVER_ERROR
            state_ok = _readback_ok(diff, state)

        result = AssertionResult(
            diff.expectation,
            DiffResponse(base.status, base.body),
            DiffResponse(assertion.status, assertion.body),
            refused,
            structure_same,
            state_ok,
        )
        return decide_diff_outcome(result)
