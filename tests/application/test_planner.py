"""TDD tests for the Planner (M4 Task 3, §13 deterministic DAG).

The Planner turns the pinned TestCatalog's required classes (and any AppModel
logic-test cases) into a deterministic ExecutionPlan DAG. Every required class
becomes a step (the agent cannot subtract required coverage); higher-risk steps
depend on lower-risk recon steps (topological order); the plan digest is stable
for the same inputs.
"""
from __future__ import annotations

from secopent.application.planner import Planner
from secopent.domain.appmodel.logic import LogicTestCase, LogicTestClass
from secopent.domain.assessments.models import ExecutionPlan
from secopent.domain.catalog.models import AssetType, RequiredTestClass, TestCatalog
from secopent.domain.policy.models import RiskClass


def _catalog() -> TestCatalog:
    return TestCatalog(
        version="2026.07",
        mappings={
            AssetType.WEB_APP: (
                RequiredTestClass(
                    id="recon", cwe=("CWE-200",), owasp=("A05:2021",), risk=RiskClass.PASSIVE
                ),
                RequiredTestClass(
                    id="sqli", cwe=("CWE-89",), owasp=("A03:2021",), risk=RiskClass.ACTIVE
                ),
                RequiredTestClass(
                    id="xss", cwe=("CWE-79",), owasp=("A03:2021",), risk=RiskClass.ACTIVE
                ),
            ),
        },
    )


def _logic_case() -> LogicTestCase:
    return LogicTestCase(
        test_class=LogicTestClass.INVARIANT_VIOLATION,
        app_model_digest="sha256:" + "a" * 64,
        target="i1",
        description="violate cart.total >= 0",
        inputs=(("total", -1),),
        signature="sha256:" + "b" * 64,
    )


def test_generates_step_per_required_class() -> None:
    plan = Planner(_catalog()).generate(
        plan_id="plan-1", assessment_id="assess-1", asset_types=[AssetType.WEB_APP]
    )
    assert isinstance(plan, ExecutionPlan)
    keys = {s.key for s in plan.steps}
    # All three required classes are present (no subtraction).
    assert keys == {"web_app:recon", "web_app:sqli", "web_app:xss"}


def test_step_risk_comes_from_required_class() -> None:
    plan = Planner(_catalog()).generate(
        plan_id="plan-1", assessment_id="assess-1", asset_types=[AssetType.WEB_APP]
    )
    by_key = {s.key: s for s in plan.steps}
    assert by_key["web_app:recon"].risk is RiskClass.PASSIVE
    assert by_key["web_app:sqli"].risk is RiskClass.ACTIVE


def test_active_steps_depend_on_recon() -> None:
    plan = Planner(_catalog()).generate(
        plan_id="plan-1", assessment_id="assess-1", asset_types=[AssetType.WEB_APP]
    )
    by_key = {s.key: s for s in plan.steps}
    # Active exploitation steps depend on the passive recon step (DAG order).
    assert "web_app:recon" in by_key["web_app:sqli"].dependencies
    # Recon has no dependencies.
    assert by_key["web_app:recon"].dependencies == ()


def test_plan_has_digest() -> None:
    plan = Planner(_catalog()).generate(
        plan_id="plan-1", assessment_id="assess-1", asset_types=[AssetType.WEB_APP]
    )
    assert plan.digest.startswith("sha256:")


def test_plan_is_deterministic() -> None:
    planner = Planner(_catalog())
    a = planner.generate(plan_id="p", assessment_id="a", asset_types=[AssetType.WEB_APP])
    b = planner.generate(plan_id="p", assessment_id="a", asset_types=[AssetType.WEB_APP])
    assert a.digest == b.digest


def test_logic_cases_add_steps() -> None:
    plan = Planner(_catalog()).generate(
        plan_id="plan-1",
        assessment_id="assess-1",
        asset_types=[AssetType.WEB_APP],
        logic_cases=[_logic_case()],
    )
    logic_steps = [s for s in plan.steps if s.key.startswith("logic:")]
    assert len(logic_steps) == 1
    assert logic_steps[0].parameters["case_signature"] == _logic_case().signature


def test_no_required_classes_yields_empty_plan() -> None:
    plan = Planner(_catalog()).generate(
        plan_id="plan-1", assessment_id="assess-1", asset_types=[AssetType.CLOUD_ACCOUNT]
    )
    assert plan.steps == ()
