# src/secopent/infrastructure/adapters/real_scan.py
"""RealScanRunner: run real tool containers and parse their output (Phase A3).

Bridges the digest-pinned IMAGE_CATALOG, the SubprocessContainerExecutor (real
``docker run``), and each adapter's ``parse`` into one call: pick an adapter,
give it tool args + mounts, get back normalized Observations parsed from the
tool's real stdout. This is the production scan path the e2e_real tests (and the
full assessment wiring) use; the AdapterRunner's mock-based unit tests stay
separate.

Example::

    runner = RealScanRunner()
    result = runner.scan(
        "nuclei",
        args=["-t", "/templates/", "-u", "http://host.docker.internal:3000",
              "-jsonl", "-silent", "-duc"],
        mounts={"/templates": host_template_dir},
    )
    for observation in result.observations: ...
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from secopent.domain.adapters.contracts import AdapterSource, Observation
from secopent.infrastructure.observability.metrics import time_adapter_run
from secopent.integrations.adapters import (
    checkov,
    dalfox,
    katana,
    kube_bench,
    naabu,
    nmap,
    nuclei,
    prowler,
    schemathesis,
    scoutsuite,
    subfinder,
    trivy,
)
from secopent.integrations.adapters import (
    httpx as httpx_adapter,
)

from .image_catalog import IMAGE_CATALOG
from .subprocess_executor import SubprocessContainerExecutor

# adapter_key -> parse(stdout=, source=, artifacts=) -> tuple[Observation, ...]
_ADAPTER_PARSERS: dict[str, Any] = {
    # Asset mapping + web/API + network (Phase A3).
    "nuclei": nuclei.parse,
    "subfinder": subfinder.parse,
    "httpx": httpx_adapter.parse,
    "naabu": naabu.parse,
    "nmap": nmap.parse,
    "dalfox": dalfox.parse,
    "katana": katana.parse,
    # API fuzzing.
    "schemathesis": schemathesis.parse,
    # Cloud / container (P3 §3.2 / T5 - completes the four-domain coverage).
    "trivy": trivy.parse,
    "prowler": prowler.parse,
    "kube_bench": kube_bench.parse,
    "checkov": checkov.parse,
    "scoutsuite": scoutsuite.parse,
}

_DEFAULT_RESOURCE_LIMITS: dict[str, Any] = {"memory": "512m", "cpus": "0.5"}


@dataclass(frozen=True, slots=True)
class RealScanResult:
    """The outcome of a real tool scan: parsed observations + raw execution info."""

    adapter_key: str
    observations: tuple[Observation, ...]
    exit_code: int
    stdout: str
    stderr: str


class RealScanRunner:
    """Run digest-pinned tool containers and parse their real output."""

    def __init__(
        self,
        executor: SubprocessContainerExecutor | None = None,
        default_timeout: int = 600,
    ) -> None:
        self._executor = executor or SubprocessContainerExecutor(
            default_timeout=default_timeout
        )

    @staticmethod
    def image_ref(adapter_key: str) -> str:
        """The digest-pinned image reference for an adapter (name@digest)."""
        image = IMAGE_CATALOG[adapter_key]
        if image.digest:
            return f"{image.name}@{image.digest}"
        return f"{image.name}:{image.tag}"

    def scan(
        self,
        adapter_key: str,
        *,
        args: list[str],
        mounts: dict[str, str] | None = None,
        source: AdapterSource | None = None,
        resource_limits: dict[str, Any] | None = None,
    ) -> RealScanResult:
        """Run the adapter's tool container and parse its stdout into Observations."""
        parser = _ADAPTER_PARSERS.get(adapter_key)
        if parser is None:
            raise ValueError(f"no parser registered for adapter {adapter_key!r}")
        with time_adapter_run(adapter_key):
            result = self._executor.run(
                image_digest=self.image_ref(adapter_key),
                command=list(args),
                mounts=dict(mounts or {}),
                network_policy="bridge",
                resource_limits=dict(resource_limits or _DEFAULT_RESOURCE_LIMITS),
            )
            scan_source = source or AdapterSource(
                name=adapter_key, version="1.0.0", template_version="1.0.0"
            )
            observations = parser(stdout=result.stdout, source=scan_source, artifacts={})
        return RealScanResult(
            adapter_key=adapter_key,
            observations=observations,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
        )
