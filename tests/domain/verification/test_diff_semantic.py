# tests/domain/verification/test_diff_semantic.py
"""Domain tests for DIFF_SEMANTIC confirmation (spec §5, Task 1 + Task 2)."""
from __future__ import annotations

import pytest

from secopent.domain.common.errors import DomainValidationError
from secopent.domain.verification.diff_semantic import (
    AssertionResult,
    DiffResponse,
    DiffSemanticPayload,
    Expectation,
    decide_diff_outcome,
)
from secopent.domain.verification.models import (
    CandidateFinding,
    ReproductionStatus,
    VerificationMethod,
    VulnType,
)


def _payload() -> DiffSemanticPayload:
    return DiffSemanticPayload(
        candidate_id="c1",
        baseline_request={"method": "GET", "url": "/api/orders/1001", "session": "userA"},
        assertion_request={"method": "GET", "url": "/api/orders/1002", "session": "userA"},
        expectation=Expectation.DENY,
        state_readback="/api/balance",
    )


class TestVerificationMethod:
    def test_diff_semantic_default_false(self) -> None:
        m = VerificationMethod(vuln_type=VulnType.IDOR, default_n=3)
        assert m.diff_semantic is False

    def test_diff_semantic_true(self) -> None:
        m = VerificationMethod(vuln_type=VulnType.IDOR, default_n=3, diff_semantic=True)
        assert m.diff_semantic is True

    def test_echo_and_diff_mutually_exclusive(self) -> None:
        with pytest.raises(DomainValidationError):
            VerificationMethod(
                vuln_type=VulnType.IDOR,
                default_n=3,
                echo_enabled=True,
                diff_semantic=True,
            )


class TestDiffSemanticPayload:
    def test_frozen_valid(self) -> None:
        p = _payload()
        assert p.expectation is Expectation.DENY
        assert p.state_readback == "/api/balance"

    def test_requires_non_empty_baseline_request(self) -> None:
        with pytest.raises(DomainValidationError):
            DiffSemanticPayload(
                candidate_id="c1",
                baseline_request={},
                assertion_request={"method": "GET", "url": "/b"},
                expectation=Expectation.DENY,
            )

    def test_requires_non_empty_assertion_request(self) -> None:
        with pytest.raises(DomainValidationError):
            DiffSemanticPayload(
                candidate_id="c1",
                baseline_request={"method": "GET", "url": "/a"},
                assertion_request={},
                expectation=Expectation.DENY,
            )

    def test_requires_candidate_id(self) -> None:
        with pytest.raises(DomainValidationError):
            DiffSemanticPayload(
                candidate_id="",
                baseline_request={},
                assertion_request={},
                expectation=Expectation.DENY,
            )


class TestCandidateFindingDiff:
    def test_candidate_carries_diff(self) -> None:
        c = CandidateFinding(
            id="c1",
            observation_id="o1",
            vuln_type=VulnType.IDOR,
            target="https://x",
            diff=_payload(),
        )
        assert c.diff is not None

    def test_candidate_without_diff_default_none(self) -> None:
        c = CandidateFinding(
            id="c1",
            observation_id="o1",
            vuln_type=VulnType.IDOR,
            target="https://x",
        )
        assert c.diff is None


class TestDecideDiffOutcome:
    # DENY / SINGLE_SPEND: finding = "越权未被拒"，确认在 override 被实体化时成立
    # （B 未拒 AND 与允许的 baseline A 同结构）。

    def test_deny_confirmed_when_B_200_same_struct(self) -> None:
        r = AssertionResult(
            Expectation.DENY,
            DiffResponse(200, {"id": 1002}),
            DiffResponse(200, {"id": 1002}),
            refused=False,
            structure_same=True,
            state_ok=None,
        )
        assert decide_diff_outcome(r) is ReproductionStatus.SUCCESS

    def test_deny_refuted_when_B_refused(self) -> None:
        r = AssertionResult(
            Expectation.DENY,
            DiffResponse(200, {"id": 1002}),
            DiffResponse(403, None),
            refused=True,
            structure_same=False,
            state_ok=None,
        )
        assert decide_diff_outcome(r) is ReproductionStatus.FAILURE

    def test_deny_inconclusive_when_struct_incomparable(self) -> None:
        r = AssertionResult(
            Expectation.DENY,
            DiffResponse(200, {"a": 1}),
            DiffResponse(200, {"b": 2}),
            refused=False,
            structure_same=False,
            state_ok=None,
        )
        assert decide_diff_outcome(r) is ReproductionStatus.SERVER_ERROR

    # STATE_REJECT 与 DENY 判据相反：确认在非法迁移未被拒（绕过）时成立，
    # 不依赖结构可比性。

    def test_state_reject_confirmed_when_migration_not_refused(self) -> None:
        r = AssertionResult(
            Expectation.STATE_REJECT,
            DiffResponse(200, {}),
            DiffResponse(200, {"new": "term"}),
            refused=False,
            structure_same=False,
            state_ok=None,
        )
        assert decide_diff_outcome(r) is ReproductionStatus.SUCCESS

    def test_state_reject_refuted_when_refused(self) -> None:
        r = AssertionResult(
            Expectation.STATE_REJECT,
            DiffResponse(200, {}),
            DiffResponse(403, None),
            refused=True,
            structure_same=False,
            state_ok=None,
        )
        assert decide_diff_outcome(r) is ReproductionStatus.FAILURE

    # SINGLE_SPEND 额外使用状态回读：读回坏状态 => FAILURE。

    def test_single_spend_uses_readback(self) -> None:
        r = AssertionResult(
            Expectation.SINGLE_SPEND,
            DiffResponse(200, {}),
            DiffResponse(200, {}),
            refused=False,
            structure_same=True,
            state_ok=True,
        )
        assert decide_diff_outcome(r) is ReproductionStatus.SUCCESS

    def test_single_spend_fails_when_readback_bad(self) -> None:
        r = AssertionResult(
            Expectation.SINGLE_SPEND,
            DiffResponse(200, {}),
            DiffResponse(200, {}),
            refused=False,
            structure_same=True,
            state_ok=False,
        )
        assert decide_diff_outcome(r) is ReproductionStatus.FAILURE

    # STATE_CHANGE 镜像 STATE_REJECT（不依赖结构可比性）。

    def test_state_change_confirmed_when_migration_not_refused(self) -> None:
        r = AssertionResult(
            Expectation.STATE_CHANGE,
            DiffResponse(200, {}),
            DiffResponse(200, {"state": "active"}),
            refused=False,
            structure_same=False,
            state_ok=None,
        )
        assert decide_diff_outcome(r) is ReproductionStatus.SUCCESS

    def test_state_change_refuted_when_refused(self) -> None:
        r = AssertionResult(
            Expectation.STATE_CHANGE,
            DiffResponse(200, {}),
            DiffResponse(403, None),
            refused=True,
            structure_same=False,
            state_ok=None,
        )
        assert decide_diff_outcome(r) is ReproductionStatus.FAILURE

    # 未知 expectation / 无匹配分支 => SERVER_ERROR（绝不反射 REFUTE）。
    # Expectation 是封闭 StrEnum，无法构造未知成员；直接以原始字符串灌入
    # dataclass 字段（frozen dataclass 不做运行时类型检查）以触达回退分支。

    def test_unknown_expectation_is_inconclusive(self) -> None:
        r = AssertionResult(
            "some_future",
            DiffResponse(200, {}),
            DiffResponse(200, {}),
            refused=False,
            structure_same=True,
            state_ok=None,
        )
        assert decide_diff_outcome(r) is ReproductionStatus.SERVER_ERROR

    def test_single_spend_readback_bad_wins_over_structure(self) -> None:
        # state_ok=False（读回坏状态）优先于拒绝/结构判据 => FAILURE（SINGLE_SPEND）。
        r = AssertionResult(
            Expectation.SINGLE_SPEND,
            DiffResponse(200, {}),
            DiffResponse(200, {}),
            refused=False,
            structure_same=True,
            state_ok=False,
        )
        assert decide_diff_outcome(r) is ReproductionStatus.FAILURE
