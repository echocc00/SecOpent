# tests/infrastructure/test_step_runner.py
"""TDD tests for AdapterStepRunner (P3 §3.2 / T5).

AdapterStepRunner is the missing glue between the Planner's PlanStep
(catalog-oriented: *which required test class*) and the RealScanRunner
(invocation-oriented: adapter + docker args + mounts). The Planner deliberately
keeps target URLs / template paths OUT of ``PlanStep.parameters`` (they are
engagement-scoped, not plan-intrinsic), so the runner carries them in a
``ScanContext``.

These tests drive it with a fake scanner (no Docker) and pin the contract:

* ``run`` maps ``step.runner`` -> adapter_key, builds the invocation from the
  step + context, scans every target, and returns a ``StepResult`` whose
  ``result_digest`` is the canonical digest of the produced observations (a
  meaningful content digest for audit + job idempotency);
* observations flow back through a per-step side channel (``observations_for`` /
  ``all_observations``) - the ``StepRunner`` Protocol returns a digest only;
* unknown adapter / empty targets raise ``StepFailure(INPUT_INVALID)`` (the
  orchestrator classifies that as a non-retryable failure, not a crash);
* it structurally satisfies the ``StepRunner`` Protocol.
"""
from __future__ import annotations

from typing import Any

import pytest

from secopent.application.orchestrator import StepFailure, StepResult
from secopent.domain.adapters.contracts import (
    AdapterSource,
    CoverageDomain,
    Observation,
    Severity,
)
from secopent.domain.assessments.models import PlanStep
from secopent.domain.common.canonical import canonical_digest
from secopent.domain.jobs.models import FailureClass
from secopent.domain.policy.models import RiskClass
from secopent.infrastructure.adapters.real_scan import (
    ContainerExecError,
    RealScanResult,
)
from secopent.infrastructure.adapters.step_runner import AdapterStepRunner, ScanContext

_SOURCE = AdapterSource(name="nuclei", version="1.0.0", template_version="1.0.0")


def _obs(external_id: str = "o1", cwe: tuple[str, ...] = ("CWE-89",)) -> Observation:
    return Observation(
        external_id=external_id,
        asset_identity="http://target:3000",
        source=_SOURCE,
        rule_id="juice-shop-login-sqli",
        rule_version="1.0.0",
        coverage_domain=CoverageDomain.WEB,
        title="SQLi bypass",
        severity=Severity.HIGH,
        confidence=0.9,
        cwe=cwe,
        owasp=("A03:2021",),
    )


def _nuclei_step(key: str = "web_app:sqli") -> PlanStep:
    return PlanStep(
        key=key,
        runner="nuclei",
        risk=RiskClass.ACTIVE,
        parameters={"asset_type": "web_app", "test_class": "sqli", "cwe": ("CWE-89",)},
        dependencies=(),
    )


class FakeScanner:
    """Stands in for RealScanRunner: records calls, returns canned observations."""

    def __init__(
        self,
        observations: tuple[Observation, ...] = (),
        *,
        fail_key: str | None = None,
        exit_code: int = 0,
        stderr: str = "",
    ) -> None:
        self._observations = observations
        self._fail_key = fail_key
        self._exit_code = exit_code
        self._stderr = stderr
        self.calls: list[dict[str, Any]] = []

    def scan(
        self,
        adapter_key: str,
        *,
        args: list[str],
        mounts: dict[str, str] | None = None,
        **_: object,
    ) -> RealScanResult:
        self.calls.append(
            {"adapter_key": adapter_key, "args": list(args), "mounts": dict(mounts or {})}
        )
        if adapter_key == self._fail_key:
            raise ValueError(f"no parser registered for adapter {adapter_key!r}")
        return RealScanResult(
            adapter_key=adapter_key,
            observations=self._observations,
            exit_code=self._exit_code,
            stdout="{}",
            stderr=self._stderr,
        )


def _runner(
    scanner: FakeScanner, targets: tuple[str, ...] = ("http://target:3000",)
) -> AdapterStepRunner:
    return AdapterStepRunner(
        scanner,  # type: ignore[arg-type]  # structural duck-typing of RealScanRunner
        ScanContext(targets=targets, template_host_dir="/host/templates"),
    )


# --- run() -> StepResult contract -------------------------------------------


def test_run_scans_target_and_returns_observations_digest() -> None:
    scanner = FakeScanner(observations=(_obs("o1"), _obs("o2", cwe=("CWE-79",))))
    runner = _runner(scanner)

    result = runner.run(_nuclei_step())

    assert isinstance(result, StepResult)
    # One scan call, correct adapter, target + template mount wired into the args.
    assert len(scanner.calls) == 1
    call = scanner.calls[0]
    assert call["adapter_key"] == "nuclei"
    assert "-u" in call["args"] and "http://target:3000" in call["args"]
    assert call["mounts"] == {"/templates": "/host/templates"}
    # result_digest is the canonical digest of the produced observations.
    assert result.result_digest == canonical_digest(scanner._observations)


def test_run_scans_every_target_and_merges_observations() -> None:
    scanner = FakeScanner(observations=(_obs(),))
    runner = _runner(scanner, targets=("http://a:3000", "http://b:3000"))

    runner.run(_nuclei_step())

    assert len(scanner.calls) == 2  # one real scan per target
    assert [c["args"][c["args"].index("-u") + 1] for c in scanner.calls] == [
        "http://a:3000",
        "http://b:3000",
    ]
    assert len(runner.observations_for("web_app:sqli")) == 2  # merged across targets


# --- observation side channel -----------------------------------------------


def test_observations_collected_per_step_and_globally() -> None:
    scanner = FakeScanner(observations=(_obs("o1"),))
    runner = _runner(scanner)
    runner.run(_nuclei_step("web_app:sqli"))
    runner.run(_nuclei_step("web_app:xss"))

    assert len(runner.observations_for("web_app:sqli")) == 1
    assert len(runner.observations_for("web_app:xss")) == 1
    assert len(runner.all_observations()) == 2
    assert runner.observations_for("unknown") == ()  # absent step -> empty


def test_digest_is_deterministic_and_content_sensitive() -> None:
    obs_a = (_obs("o1"),)
    runner_a = _runner(FakeScanner(observations=obs_a))
    runner_b = _runner(FakeScanner(observations=obs_a))
    runner_c = _runner(FakeScanner(observations=(_obs("different"),)))

    result_a = runner_a.run(_nuclei_step())
    result_b = runner_b.run(_nuclei_step())
    result_c = runner_c.run(_nuclei_step())

    assert result_a.result_digest == result_b.result_digest  # same obs -> same digest
    assert result_a.result_digest != result_c.result_digest  # diff obs -> diff digest
    assert result_a.result_digest.startswith("sha256:")


# --- failure classification --------------------------------------------------


def test_unknown_adapter_raises_input_invalid_step_failure() -> None:
    scanner = FakeScanner(fail_key="ghost")
    runner = AdapterStepRunner(
        scanner,  # type: ignore[arg-type]
        ScanContext(targets=("http://target:3000",)),
    )
    step = PlanStep(
        key="web_app:sqli", runner="ghost", risk=RiskClass.ACTIVE, parameters={}, dependencies=()
    )
    with pytest.raises(StepFailure) as excinfo:
        runner.run(step)
    assert "ghost" in str(excinfo.value)


def test_empty_targets_raises_input_invalid_step_failure() -> None:
    runner = AdapterStepRunner(
        FakeScanner(),  # type: ignore[arg-type]
        ScanContext(targets=()),
    )
    with pytest.raises(StepFailure):
        runner.run(_nuclei_step())


def test_nonzero_exit_code_raises_worker_unavailable_step_failure() -> None:
    """v8 root cause 2: a container that exits non-zero must be a step FAILURE,
    never a silent 'success' with zero observations."""
    scanner = FakeScanner(observations=(), exit_code=3, stderr="no templates found")
    runner = _runner(scanner)

    with pytest.raises(StepFailure) as excinfo:
        runner.run(_nuclei_step())

    assert excinfo.value.failure_class is FailureClass.WORKER_UNAVAILABLE
    assert "exit_code=3" in str(excinfo.value)
    assert "no templates found" in str(excinfo.value)


def test_container_launch_exception_classified_worker_unavailable() -> None:
    """A docker-run crash (not a parse error) is a transient worker failure."""

    class _ExplodingScanner(FakeScanner):
        def scan(self, adapter_key, *, args, mounts=None, **_: object):  # type: ignore[override]
            raise ContainerExecError("Error: No such file or directory")

    runner = AdapterStepRunner(
        _ExplodingScanner(),  # type: ignore[arg-type]
        ScanContext(targets=("http://target:3000",)),
    )
    with pytest.raises(StepFailure) as excinfo:
        runner.run(_nuclei_step())
    assert excinfo.value.failure_class is FailureClass.WORKER_UNAVAILABLE
    assert "No such file or directory" in str(excinfo.value)


def test_container_launch_failure_mention_docker_logs_hint() -> None:
    """v8 §3.2: a container launch failure must surface a `docker logs` hint
    so the operator can diagnose without Docker socket access."""

    class _ExplodingScanner(FakeScanner):
        def scan(self, adapter_key, *, args, mounts=None, **_: object):  # type: ignore[override]
            raise ContainerExecError(
                "container launch failed for nuclei: docker: Error response "
                "from daemon: No such file or directory"
            )

    runner = AdapterStepRunner(
        _ExplodingScanner(),  # type: ignore[arg-type]
        ScanContext(targets=("http://target:3000",)),
    )
    with pytest.raises(StepFailure) as excinfo:
        runner.run(_nuclei_step())
    assert "docker logs" in str(excinfo.value)


# --- engagement-wide mounts + cloud invocation ------------------------------


def test_extra_mounts_merged_into_every_invocation() -> None:
    scanner = FakeScanner(observations=(_obs(),))
    runner = AdapterStepRunner(
        scanner,  # type: ignore[arg-type]
        ScanContext(
            targets=("http://target:3000",),
            template_host_dir="/host/templates",
            extra_mounts=(("/var/run/docker.sock", "/var/run/docker.sock"),),
        ),
    )
    runner.run(_nuclei_step())
    call = scanner.calls[0]
    # The template mount AND the engagement-wide docker-socket mount are present.
    assert call["mounts"]["/templates"] == "/host/templates"
    assert call["mounts"]["/var/run/docker.sock"] == "/var/run/docker.sock"


def test_trivy_invocation_is_an_image_scan_with_extra_mounts() -> None:
    scanner = FakeScanner(observations=())
    runner = AdapterStepRunner(
        scanner,  # type: ignore[arg-type]
        ScanContext(
            targets=("bkimminich/juice-shop:latest",),
            extra_mounts=(("/var/run/docker.sock", "/var/run/docker.sock"),),
        ),
    )
    step = PlanStep(
        key="container:cve", runner="trivy", risk=RiskClass.PASSIVE, parameters={}, dependencies=()
    )
    result = runner.run(step)
    call = scanner.calls[0]
    assert call["adapter_key"] == "trivy"
    assert call["args"][:2] == ["image", "--format"]  # trivy image sub-command
    assert "bkimminich/juice-shop:latest" in call["args"]
    assert call["mounts"] == {"/var/run/docker.sock": "/var/run/docker.sock"}
    assert result.result_digest == canonical_digest(())  # no obs -> empty digest


def test_checkov_invocation_scans_the_mounted_iac_dir() -> None:
    scanner = FakeScanner(observations=())
    runner = AdapterStepRunner(
        scanner,  # type: ignore[arg-type]
        ScanContext(targets=("iac-scan",), template_host_dir="/host/iac"),
    )
    step = PlanStep(
        key="cloud:iac", runner="checkov", risk=RiskClass.PASSIVE, parameters={}, dependencies=()
    )
    runner.run(step)
    call = scanner.calls[0]
    assert call["adapter_key"] == "checkov"
    assert "--directory" in call["args"] and "/templates" in call["args"]
    assert "--output" in call["args"] and "json" in call["args"]
    assert call["mounts"] == {"/templates": "/host/iac"}  # IaC dir mounted


def test_nmap_invocation_scans_in_scope_ports() -> None:
    scanner = FakeScanner(observations=())
    runner = AdapterStepRunner(
        scanner,  # type: ignore[arg-type]
        ScanContext(targets=("host.docker.internal",), ports=(8080, 3000)),
    )
    step = PlanStep(
        key="net:ports", runner="nmap", risk=RiskClass.PASSIVE, parameters={}, dependencies=()
    )
    runner.run(step)
    call = scanner.calls[0]
    assert call["adapter_key"] == "nmap"
    assert "-p" in call["args"] and "8080,3000" in call["args"]
    assert "-oX" in call["args"] and "host.docker.internal" in call["args"]


def test_naabu_invocation_targets_host_and_ports() -> None:
    scanner = FakeScanner(observations=())
    runner = AdapterStepRunner(
        scanner,  # type: ignore[arg-type]
        ScanContext(targets=("host.docker.internal",), ports=(8080,)),
    )
    step = PlanStep(
        key="net:naabu", runner="naabu", risk=RiskClass.PASSIVE, parameters={}, dependencies=()
    )
    runner.run(step)
    call = scanner.calls[0]
    assert call["adapter_key"] == "naabu"
    assert "-host" in call["args"] and "host.docker.internal" in call["args"]
    assert "-p" in call["args"] and "8080" in call["args"]


def test_httpx_invocation_probes_url() -> None:
    scanner = FakeScanner(observations=())
    runner = AdapterStepRunner(
        scanner,  # type: ignore[arg-type]
        ScanContext(targets=("http://host.docker.internal:8080",)),
    )
    step = PlanStep(
        key="asset:probe", runner="httpx", risk=RiskClass.PASSIVE, parameters={}, dependencies=()
    )
    runner.run(step)
    call = scanner.calls[0]
    assert call["adapter_key"] == "httpx"
    assert "-u" in call["args"] and "http://host.docker.internal:8080" in call["args"]


def test_dalfox_invocation_leads_with_binary_name() -> None:
    scanner = FakeScanner(observations=())
    runner = AdapterStepRunner(
        scanner,  # type: ignore[arg-type]
        ScanContext(targets=("http://host.docker.internal:3000/?q=test",)),
    )
    step = PlanStep(
        key="web:xss", runner="dalfox", risk=RiskClass.ACTIVE, parameters={}, dependencies=()
    )
    runner.run(step)
    call = scanner.calls[0]
    assert call["adapter_key"] == "dalfox"
    # The dalfox image has no ENTRYPOINT, so the binary name must lead.
    assert call["args"][0] == "dalfox" and call["args"][1] == "url"
    assert "http://host.docker.internal:3000/?q=test" in call["args"]


# --- Protocol conformance ----------------------------------------------------


def test_satisfies_step_runner_protocol() -> None:
    from secopent.application.orchestrator import StepRunner

    assert isinstance(_runner(FakeScanner()), StepRunner)
