# src/secopent/infrastructure/adapters/step_runner.py
"""AdapterStepRunner: the StepRunner glue for real orchestration (P3 §3.2 / T5).

This is the integration layer the Planner and the real adapter plane were
missing. The Planner emits catalog-oriented ``PlanStep`` parameters - *which
required test class* (``asset_type``/``test_class``/``cwe``/``owasp``) - and
deliberately keeps engagement-scoped inputs (target URLs, rule/template paths)
OUT of the plan, because the plan is a pure function of the catalog while the
targets are a property of the engagement. ``AdapterStepRunner`` supplies those
engagement inputs via a ``ScanContext`` and translates each step into a real
tool-container scan through the proven :class:`RealScanRunner`.

It implements the application-layer ``StepRunner`` Protocol structurally (the
implementation lives in infrastructure so the docker execution stays out of the
framework-free domain/application layers)::

    run(step: PlanStep) -> StepResult(result_digest=...)

Observations are NOT carried on ``StepResult`` - the Protocol returns a content
digest only, and ``Job`` persists just that digest. They are collected in a
per-step side channel (``observations_for`` / ``all_observations``) that the
assessment/orchestration layer reads after ``run_to_completion`` - the same way
the production scan path already collects them. The returned ``result_digest``
is the canonical digest of the step's observations, so it is a genuine content
digest for the audit chain and job idempotency (matching the field's docstring).

Failure semantics honour the orchestrator: an unknown adapter or an empty target
set raises ``StepFailure(INPUT_INVALID)`` so the orchestrator records a
non-retryable FAILED job rather than the worker crashing.
"""
from __future__ import annotations

from dataclasses import dataclass

from secopent.application.orchestrator import StepFailure, StepResult
from secopent.domain.adapters.contracts import Observation
from secopent.domain.assessments.models import PlanStep
from secopent.domain.common.canonical import canonical_digest
from secopent.domain.jobs.models import FailureClass

from .real_scan import RealScanResult, RealScanRunner

# Adapters driven by a mounted rule/template directory (nuclei-style `-t <dir>`).
_TEMPLATE_ADAPTERS = frozenset({"nuclei", "nuclei_tcp"})

# Default container mount point for the rule/template directory.
_DEFAULT_TEMPLATE_MOUNT = "/templates"


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Engagement-scoped execution inputs the plan deliberately does not carry.

    ``targets``: base URLs / hosts / scan refs in scope; one real scan runs per
        target and the observations are merged under the step key.
    ``template_host_dir``: host directory holding the scan's input files (nuclei
        templates, or IaC manifests for a cloud scanner) mounted read-only into
        the container; ``None`` means the tool runs with its built-in defaults.
    ``template_container_path``: the in-container mount point for that directory.
    ``extra_mounts``: additional ``(destination, source)`` bind mounts applied to
        every scan of this engagement - e.g. the docker socket so a cloud/container
        scanner (trivy) can inspect the host daemon's local images.
    """

    targets: tuple[str, ...]
    template_host_dir: str | None = None
    template_container_path: str = _DEFAULT_TEMPLATE_MOUNT
    extra_mounts: tuple[tuple[str, str], ...] = ()
    # Ports in scope for port scanners (nmap/naabu); empty means the tool's own
    # default (e.g. nmap top-100). Engagement-scoped, like ScopeSnapshot.ports.
    ports: tuple[int, ...] = ()


class AdapterStepRunner:
    """Execute plan steps as real tool-container scans (``StepRunner`` Protocol).

    Constructed per engagement with a :class:`RealScanRunner` and a
    :class:`ScanContext`. Not thread-safe for concurrent ``run`` on the *same*
    instance's internal dict; the Orchestrator's parallel path leases distinct
    jobs, and V1 runs a single worker per orchestrator, so each worker owns its
    runner instance.
    """

    def __init__(self, scan_runner: RealScanRunner, context: ScanContext) -> None:
        self._scanner = scan_runner
        self._context = context
        self._observations: dict[str, tuple[Observation, ...]] = {}

    # -- StepRunner Protocol --------------------------------------------------

    def run(self, step: PlanStep) -> StepResult:
        """Scan every in-scope target with the step's adapter; digest the result."""
        if not self._context.targets:
            raise StepFailure(
                FailureClass.INPUT_INVALID, "scan context has no targets"
            )
        merged: list[Observation] = []
        for target in self._context.targets:
            merged.extend(self._scan_target(step, target).observations)
        stored = tuple(merged)
        self._observations[step.key] = stored
        return StepResult(result_digest=self._digest(stored))

    # -- observation side channel ---------------------------------------------

    def observations_for(self, step_key: str) -> tuple[Observation, ...]:
        """Observations produced by one step (empty tuple if the step never ran)."""
        return self._observations.get(step_key, ())

    def all_observations(self) -> tuple[Observation, ...]:
        """Every observation produced across all executed steps, in run order."""
        merged: list[Observation] = []
        for observations in self._observations.values():
            merged.extend(observations)
        return tuple(merged)

    # -- internals ------------------------------------------------------------

    def _scan_target(self, step: PlanStep, target: str) -> RealScanResult:
        args, mounts = self._invocation(step.runner, target)
        try:
            return self._scanner.scan(step.runner, args=args, mounts=mounts)
        except ValueError as exc:  # unknown adapter_key / no registered parser
            raise StepFailure(FailureClass.INPUT_INVALID, str(exc)) from exc

    def _invocation(self, adapter_key: str, target: str) -> tuple[list[str], dict[str, str]]:
        """Map (adapter, target) + context onto tool CLI args and mounts."""
        # Engagement-wide bind mounts (e.g. the docker socket for cloud scanners)
        # apply to every adapter; adapter-specific mounts are added below.
        mounts: dict[str, str] = {
            destination: source for destination, source in self._context.extra_mounts
        }
        if adapter_key in _TEMPLATE_ADAPTERS:
            args = ["-u", target, "-jsonl", "-silent", "-duc"]
            if self._context.template_host_dir:
                args = ["-t", f"{self._context.template_container_path}/", *args]
                mounts[self._context.template_container_path] = (
                    self._context.template_host_dir
                )
            return args, mounts
        if adapter_key == "nmap":
            # XML to stdout so the nmap parser can read it from the stream.
            if self._context.ports:
                return ["-p", self._ports_arg(), "--open", "-oX", "-", target], mounts
            return ["--open", "-oX", "-", target], mounts
        if adapter_key == "naabu":
            if self._context.ports:
                return ["-host", target, "-p", self._ports_arg(), "-json", "-silent"], mounts
            return ["-host", target, "-json", "-silent"], mounts
        if adapter_key == "httpx":
            return ["-u", target, "-json", "-silent"], mounts
        if adapter_key == "dalfox":
            # The dalfox image has no ENTRYPOINT, so the binary name leads the
            # command. `target` is the URL (with a query string) to fuzz for XSS.
            return ["dalfox", "url", target, "-o", "json", "--silence"], mounts
        if adapter_key == "subfinder":
            # Subdomain enumeration: target is a bare domain.
            return ["-d", target, "-json", "-silent"], mounts
        if adapter_key == "katana":
            # Web crawler: target is a URL.
            return ["-u", target, "-json", "-silent", "-d", "3"], mounts
        if adapter_key == "fingerprinthub":
            # Service fingerprinting via TCP probes: target is host:port or IP.
            return ["-t", target, "-j"], mounts
        if adapter_key == "schemathesis":
            # OpenAPI fuzzing: target is the OpenAPI spec URL.
            return ["run", target, "--report", "json", "--hypothesis-max-examples", "50"], mounts
        if adapter_key == "prowler":
            # Cloud posture scan: target is the provider (e.g. "aws").
            return [target, "-M", "json"], mounts
        if adapter_key == "kube_bench":
            # CIS benchmark for the local node (runs inside the cluster).
            return ["--json"], mounts
        if adapter_key == "scoutsuite":
            # Cloud audit: target is the provider (e.g. "aws").
            return [target, "--report-dir", "/work/output", "--json"], mounts
        if adapter_key == "zap":
            # ZAP baseline scan: target is the URL.
            return ["-t", target, "-J", "-l", "WARN"], mounts
        if adapter_key == "restler":
            # RESTler fuzz: target is the path to the compiled grammar dir.
            return ["test", "--grammar_file", target], mounts
        if adapter_key == "trivy":
            # `target` is the scan ref (image name / filesystem path).
            return ["image", "--format", "json", "--quiet", target], mounts
        if adapter_key == "checkov":
            # IaC misconfig scan of the mounted input directory; JSON to stdout.
            # checkov exits non-zero when checks fail - that IS a successful scan.
            if self._context.template_host_dir:
                mounts[self._context.template_container_path] = (
                    self._context.template_host_dir
                )
                return [
                    "--directory",
                    self._context.template_container_path,
                    "--output",
                    "json",
                    "--quiet",
                ], mounts
            # Without a template directory checkov would scan the empty /work
            # dir and silently produce zero findings (false negative). Fail
            # explicitly so the orchestrator records INPUT_INVALID.
            raise StepFailure(
                FailureClass.INPUT_INVALID,
                "checkov requires template_host_dir (IaC input directory)",
            )
        # Conservative default: the target as the sole positional argument.
        return [target], mounts

    def _ports_arg(self) -> str:
        """Comma-separated in-scope ports for port scanners (nmap/naabu)."""
        return ",".join(str(port) for port in self._context.ports)

    @staticmethod
    def _digest(observations: tuple[Observation, ...]) -> str:
        return canonical_digest(observations)
