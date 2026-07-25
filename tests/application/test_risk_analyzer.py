"""TDD tests for RiskAnalyzer (M2 Task 8, §11.6 static publish gate).

The RiskAnalyzer statically computes a case's action risk from its DSL steps and
enforces two publish rules:
- patterns that must never publish (Shell / unbounded loop / out-of-scope target)
  -> publish denied;
- the declared risk must be >= the computed risk (you may declare a higher risk
  than you compute, never a lower one).

Risk ladder (§11.6): GET/HEAD = Low; crawl/scan = Active;
credential/upload/timing/OAST = Intrusive; Shell/unbounded/oos = deny.
"""
from __future__ import annotations

import pytest

from secopent.application.risk_analyzer import RiskAnalyzer
from secopent.domain.cases.models import CaseDefinition, CaseStep
from secopent.domain.cases.risk import (
    RiskPublishDenied,
    RiskUndeclared,
    compute_risk,
)
from secopent.domain.policy.models import RiskClass


def _case(*steps: CaseStep, risk: RiskClass = RiskClass.LOW) -> CaseDefinition:
    return CaseDefinition(
        id="c",
        version="1.0.0",
        author="a",
        risk=risk,
        target_type="http",
        schema="s",
        steps=tuple(steps),
    )


def _step(action: str, **spec: object) -> CaseStep:
    return CaseStep(id="s", action=action, spec=dict(spec))


# ---------------------------------------------------------------------------
# compute_risk: static ladder
# ---------------------------------------------------------------------------


def test_get_request_computes_low() -> None:
    case = _case(_step("http.request", method="GET"))
    assert compute_risk(case) is RiskClass.LOW


def test_head_request_computes_low() -> None:
    case = _case(_step("http.request", method="HEAD"))
    assert compute_risk(case) is RiskClass.LOW


def test_crawl_computes_active() -> None:
    case = _case(_step("crawl"))
    assert compute_risk(case) is RiskClass.ACTIVE


def test_writing_method_computes_active() -> None:
    case = _case(_step("http.request", method="POST"))
    assert compute_risk(case) is RiskClass.ACTIVE


def test_oast_computes_intrusive() -> None:
    case = _case(_step("oast.wait", window=30))
    assert compute_risk(case) is RiskClass.INTRUSIVE


def test_credential_upload_timing_compute_intrusive() -> None:
    for spec in ({"credential": True}, {"upload": True}, {"time_based": True}):
        case = _case(_step("http.request", method="POST", **spec))
        assert compute_risk(case) is RiskClass.INTRUSIVE, spec


def test_max_risk_wins_across_steps() -> None:
    case = _case(_step("http.request", method="GET"), _step("oast.wait", window=30))
    assert compute_risk(case) is RiskClass.INTRUSIVE


def test_shell_computes_deny() -> None:
    case = _case(_step("shell.exec", cmd="id"))
    assert compute_risk(case) is None


def test_unbounded_foreach_computes_deny() -> None:
    case = _case(_step("foreach", items="targets"))  # no bound
    assert compute_risk(case) is None


def test_bounded_foreach_is_not_denied() -> None:
    case = _case(_step("foreach", items="targets", limit=10))
    assert compute_risk(case) is not None


def test_out_of_scope_target_computes_deny() -> None:
    case = _case(_step("http.request", method="GET", target_out_of_scope=True))
    assert compute_risk(case) is None


# ---------------------------------------------------------------------------
# RiskAnalyzer.enforce_publish
# ---------------------------------------------------------------------------


def test_enforce_passes_when_declared_meets_computed() -> None:
    case = _case(_step("oast.wait", window=30), risk=RiskClass.INTRUSIVE)
    RiskAnalyzer().enforce_publish(case)  # declared == computed -> OK


def test_enforce_passes_when_declared_exceeds_computed() -> None:
    # Declaring a HIGHER risk than computed is allowed (conservative).
    case = _case(_step("http.request", method="GET"), risk=RiskClass.ACTIVE)
    RiskAnalyzer().enforce_publish(case)


def test_enforce_rejects_declared_below_computed() -> None:
    case = _case(_step("oast.wait", window=30), risk=RiskClass.LOW)  # computed Intrusive
    with pytest.raises(RiskUndeclared):
        RiskAnalyzer().enforce_publish(case)


def test_enforce_rejects_deny_pattern() -> None:
    case = _case(_step("shell.exec", cmd="id"), risk=RiskClass.DESTRUCTIVE)
    with pytest.raises(RiskPublishDenied):
        RiskAnalyzer().enforce_publish(case)


def test_analyze_returns_computed_risk() -> None:
    case = _case(_step("crawl"), risk=RiskClass.LOW)
    assert RiskAnalyzer().analyze(case) is RiskClass.ACTIVE
