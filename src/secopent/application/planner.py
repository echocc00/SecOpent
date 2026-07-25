# src/secopent/application/planner.py
"""Planner: deterministic execution DAG from TestCatalog + AppModel (§13).

The Planner turns the pinned TestCatalog's required classes for the assessment's
asset types - plus any AppModel logic-test cases - into an ExecutionPlan DAG.
Every required class becomes a step: the agent can ADD context but never
SUBTRACT required coverage (the plan is a pure function of the catalog). Steps
are scheduled in risk tiers (passive/low recon before active exploitation, active
before intrusive) so the DAG respects "reconnaissance first". The plan digest is
stable for identical inputs.
"""
from __future__ import annotations

from collections.abc import Sequence

from ..domain.appmodel.logic import LogicTestCase
from ..domain.assessments.models import ExecutionPlan, PlanStep
from ..domain.catalog.models import AssetType, TestCatalog
from ..domain.policy.models import RiskClass

# Default adapter (runner) per asset type; overridable via runner_map.
_DEFAULT_RUNNERS: dict[AssetType, str] = {
    AssetType.WEB_APP: "nuclei",
    AssetType.API: "nuclei",
    AssetType.IP_PORT: "nmap",
    AssetType.CLOUD_ACCOUNT: "prowler",
    AssetType.CONTAINER_K8S: "trivy",
}

# Logic-test steps actively exercise the app.
_LOGIC_RISK = RiskClass.ACTIVE


class Planner:
    """Generate a deterministic ExecutionPlan DAG."""

    def __init__(
        self,
        catalog: TestCatalog,
        runner_map: dict[AssetType, str] | None = None,
    ) -> None:
        self._catalog = catalog
        self._runners = dict(_DEFAULT_RUNNERS)
        if runner_map:
            self._runners.update(runner_map)

    def generate(
        self,
        *,
        plan_id: str,
        assessment_id: str,
        asset_types: Sequence[AssetType],
        logic_cases: Sequence[LogicTestCase] = (),
        version: int = 1,
    ) -> ExecutionPlan:
        """Build the plan DAG; required classes are always included."""
        items = self._collect_items(asset_types, logic_cases)

        recon_keys = [
            key for key, _, risk, _ in items if risk in (RiskClass.PASSIVE, RiskClass.LOW)
        ]
        active_keys = [key for key, _, risk, _ in items if risk is RiskClass.ACTIVE]

        steps: list[PlanStep] = []
        for key, runner, risk, parameters in items:
            if risk in (RiskClass.PASSIVE, RiskClass.LOW):
                deps: tuple[str, ...] = ()
            elif risk is RiskClass.ACTIVE:
                deps = tuple(recon_keys)
            else:  # INTRUSIVE / DESTRUCTIVE
                deps = tuple(recon_keys + active_keys)
            steps.append(
                PlanStep(
                    key=key,
                    runner=runner,
                    risk=risk,
                    parameters=parameters,
                    dependencies=deps,
                )
            )
        return ExecutionPlan.create(
            plan_id=plan_id,
            assessment_id=assessment_id,
            version=version,
            steps=tuple(steps),
        )

    def _collect_items(
        self,
        asset_types: Sequence[AssetType],
        logic_cases: Sequence[LogicTestCase],
    ) -> list[tuple[str, str, RiskClass, dict[str, object]]]:
        """Collect (key, runner, risk, parameters) for every planned step."""
        items: list[tuple[str, str, RiskClass, dict[str, object]]] = []
        for asset_type in asset_types:
            runner = self._runners.get(asset_type, "adapter")
            for cls in self._catalog.required_for(asset_type):
                items.append(
                    (
                        f"{asset_type.value}:{cls.id}",
                        runner,
                        cls.risk,
                        {
                            "asset_type": asset_type.value,
                            "test_class": cls.id,
                            "cwe": cls.cwe,
                            "owasp": cls.owasp,
                        },
                    )
                )
        for case in logic_cases:
            sig = case.signature.removeprefix("sha256:")[:12]
            items.append(
                (
                    f"logic:{case.test_class.value}:{sig}",
                    "case-engine",
                    _LOGIC_RISK,
                    {
                        "test_class": case.test_class.value,
                        "case_signature": case.signature,
                        "app_model_digest": case.app_model_digest,
                    },
                )
            )
        return items
