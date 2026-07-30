# src/secopent/infrastructure/observability/metrics.py
"""Prometheus metrics for SecOpent (T16 / cross-cutting §③).

Five application metric families, exposed at ``/metrics`` (see the API wiring).
A dedicated ``CollectorRegistry`` keeps the app metrics isolated from the global
default (and from each other across test runs). Instrumentation helpers record
into these metrics from the application/infrastructure layers.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest

REGISTRY = CollectorRegistry()

# Assessments reaching a terminal status, by status + tenant.
assessments_total = Counter(
    "secopent_assessments_total",
    "Assessments by terminal status.",
    ["status", "tenant"],
    registry=REGISTRY,
)

# Findings correlated, by severity + oracle verdict + tenant.
findings_total = Counter(
    "secopent_findings_total",
    "Findings by severity and oracle verdict.",
    ["severity", "oracle_verdict", "tenant"],
    registry=REGISTRY,
)

# Oracle (re-scan verification) latency.
oracle_verification_seconds = Histogram(
    "secopent_oracle_verification_seconds",
    "Oracle verification latency in seconds.",
    registry=REGISTRY,
)

# LLM tokens consumed, by tenant + kind (propose/summarize/...).
llm_tokens_total = Counter(
    "secopent_llm_tokens_total",
    "LLM tokens consumed by kind.",
    ["tenant", "kind"],
    registry=REGISTRY,
)

# Adapter (tool container) run latency, by adapter key.
adapter_run_seconds = Histogram(
    "secopent_adapter_run_seconds",
    "Adapter run latency in seconds.",
    ["adapter"],
    registry=REGISTRY,
)


def render_metrics() -> bytes:
    """Render all registered metrics in the Prometheus text exposition format."""
    return generate_latest(REGISTRY)


def record_assessment(status: str, tenant: str = "default") -> None:
    assessments_total.labels(status=status, tenant=tenant).inc()


def record_finding(
    severity: str, oracle_verdict: str, tenant: str = "default"
) -> None:
    findings_total.labels(
        severity=severity, oracle_verdict=oracle_verdict, tenant=tenant
    ).inc()


def record_llm_tokens(kind: str, count: int, tenant: str = "default") -> None:
    llm_tokens_total.labels(tenant=tenant, kind=kind).inc(count)


@contextmanager
def time_oracle_verification() -> Iterator[None]:
    with oracle_verification_seconds.time():
        yield


@contextmanager
def time_adapter_run(adapter: str) -> Iterator[None]:
    with adapter_run_seconds.labels(adapter=adapter).time():
        yield
