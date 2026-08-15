"""LLMPlanner: intent-driven test-class selection with a deterministic floor
(v0.6.3 spec §4.2).

The catalog's REQUIRED classes per asset type are ALWAYS included - the LLM
may only ADD classes it deems relevant to the mission intent (never subtract).
risk_cap (or the grant's caps) filters the final set. Any LLM failure/absence
degrades to the deterministic required-only plan (never fails the mission).

Note on "add": in the CURRENT catalog model, every mapped class IS required
(mappings[asset_type] == required_for(asset_type)), so the LLM's practical
value is (a) risk-cap filtering and (b) a validated selection surface that
WILL add classes once a catalog grows optional entries outside the required
floor. The "add" machinery is tested against a catalog whose floor is a
subset of its classes.
"""
from __future__ import annotations

from secopent.application.llm_planner import LLMPlanner
from secopent.domain.catalog.models import AssetType, RequiredTestClass, TestCatalog
from secopent.domain.policy.models import RiskClass


def _cls(class_id: str, *cwe: str, risk: RiskClass = RiskClass.LOW) -> RequiredTestClass:
    return RequiredTestClass(id=class_id, cwe=cwe, owasp=(), risk=risk)


def _catalog() -> TestCatalog:
    """web_app floor: sqli + xss (both LOW)."""
    return TestCatalog(
        version="test",
        mappings={
            AssetType.WEB_APP: (
                _cls("web_app:sqli", "CWE-89", risk=RiskClass.LOW),
                _cls("web_app:xss", "CWE-79", risk=RiskClass.LOW),
            ),
        },
    )


def _catalog_with_optional() -> TestCatalog:
    """web_app floor: sqli + xss; OPTIONAL pool: xss-extra (LOW) + active-lab
    (ACTIVE). These optional classes exist in the catalog OUTSIDE the WEB_APP
    required floor (a future curation direction), so the LLM may add them."""
    return TestCatalog(
        version="test-opt",
        mappings={
            AssetType.WEB_APP: (
                _cls("web_app:sqli", "CWE-89", risk=RiskClass.LOW),
                _cls("web_app:xss", "CWE-79", risk=RiskClass.LOW),
            ),
            AssetType.API: (
                _cls("api:xss-extra", "CWE-79", risk=RiskClass.LOW),
                _cls("api:active-lab", "CWE-89", risk=RiskClass.ACTIVE),
            ),
        },
    )


class _FakeBackend:
    def __init__(self, output: str) -> None:
        self._output = output

    def complete(self, prompt: str) -> str:
        return self._output


def _keys(plan) -> list[str]:
    return [s.key for s in plan.steps]


def test_floor_classes_always_present() -> None:
    planner = LLMPlanner(backend=None, catalog=_catalog())
    plan = planner.generate(
        plan_id="p", assessment_id="a", asset_types=(AssetType.WEB_APP,),
        intent="recon",
    )
    assert set(_keys(plan)) == {"web_app:sqli", "web_app:xss"}


def test_llm_adds_class_above_the_floor() -> None:
    """LLM may add classes from a wider pool; floor never shrinks."""
    planner = LLMPlanner(
        backend=_FakeBackend('["api:xss-extra"]'), catalog=_catalog_with_optional()
    )
    plan = planner.generate(
        plan_id="p", assessment_id="a", asset_types=(AssetType.WEB_APP,),
        intent="find xss",
    )
    keys = _keys(plan)
    assert "web_app:sqli" in keys and "web_app:xss" in keys  # floor intact
    assert "api:xss-extra" in keys  # LLM addition present


def test_llm_invalid_ids_are_dropped() -> None:
    planner = LLMPlanner(
        backend=_FakeBackend('["web_app:not-real", "garbage", "api:xss-extra"]'),
        catalog=_catalog_with_optional(),
    )
    plan = planner.generate(
        plan_id="p", assessment_id="a", asset_types=(AssetType.WEB_APP,),
        intent="whatever",
    )
    keys = _keys(plan)
    assert "web_app:not-real" not in keys
    assert "web_app:sqli" in keys  # floor survives


def test_llm_null_backend_degrades_to_floor() -> None:
    planner = LLMPlanner(backend=None, catalog=_catalog_with_optional())
    plan = planner.generate(
        plan_id="p", assessment_id="a", asset_types=(AssetType.WEB_APP,),
        intent="anything",
    )
    assert set(_keys(plan)) == {"web_app:sqli", "web_app:xss"}  # floor only


def test_llm_backend_raise_degrades_to_floor() -> None:
    class _Boom:
        def complete(self, prompt: str) -> str:  # pragma: no cover
            raise RuntimeError("model down")

    planner = LLMPlanner(backend=_Boom(), catalog=_catalog_with_optional())
    plan = planner.generate(
        plan_id="p", assessment_id="a", asset_types=(AssetType.WEB_APP,),
        intent="anything",
    )
    assert set(_keys(plan)) == {"web_app:sqli", "web_app:xss"}


def test_llm_non_json_output_degrades_to_floor() -> None:
    planner = LLMPlanner(
        backend=_FakeBackend("sorry, I can't help with that"),
        catalog=_catalog_with_optional(),
    )
    plan = planner.generate(
        plan_id="p", assessment_id="a", asset_types=(AssetType.WEB_APP,),
        intent="anything",
    )
    assert set(_keys(plan)) == {"web_app:sqli", "web_app:xss"}


def test_risk_cap_filters_llm_additions() -> None:
    planner = LLMPlanner(
        backend=_FakeBackend('["api:active-lab", "api:xss-extra"]'),
        catalog=_catalog_with_optional(),
    )
    plan = planner.generate(
        plan_id="p", assessment_id="a", asset_types=(AssetType.WEB_APP,),
        intent="active stuff", risk_cap=RiskClass.LOW,
    )
    keys = _keys(plan)
    assert "api:xss-extra" in keys   # within LOW cap
    assert "api:active-lab" not in keys  # ACTIVE exceeds cap
    assert "web_app:sqli" in keys    # floor survives the cap


def test_plan_step_parameters_carry_catalog_metadata() -> None:
    planner = LLMPlanner(
        backend=_FakeBackend('["api:xss-extra"]'), catalog=_catalog_with_optional()
    )
    plan = planner.generate(
        plan_id="p", assessment_id="a", asset_types=(AssetType.WEB_APP,),
        intent="recon",
    )
    step = next(s for s in plan.steps if s.key == "web_app:sqli")
    assert step.runner == "nuclei"
    assert step.parameters["asset_type"] == "web_app"
    assert step.parameters["test_class"] == "web_app:sqli"
    assert step.parameters["cwe"] == ("CWE-89",)
    assert step.parameters["intent"] == "recon"