# src/secopent/infrastructure/observability/tracing.py
"""OpenTelemetry tracing bootstrap (T16 / cross-cutting §③).

Best-effort FastAPI auto-instrumentation: when the OpenTelemetry SDK is present,
incoming requests and their spans are exported via whatever exporter the
deployment configures (OTLP, console, or none). Tracing must never break the app,
so every failure degrades to a no-op.
"""
from __future__ import annotations

from fastapi import FastAPI


def setup_tracing(app: FastAPI, *, service_name: str = "secopent-api") -> bool:
    """Instrument the FastAPI app with OpenTelemetry; return True if enabled.

    No-op (returns False) when the OTel instrumentation package is missing or
    instrumentation fails - tracing is optional and must not affect correctness.
    """
    try:
        from opentelemetry import trace
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider

        # Only install a provider if one is not already configured, so a
        # deployment's own OTel setup (exporters, samplers) is respected.
        if not isinstance(trace.get_tracer_provider(), TracerProvider):
            trace.set_tracer_provider(
                TracerProvider(resource=Resource.create({"service.name": service_name}))
            )
        FastAPIInstrumentor.instrument_app(app)
        return True
    except Exception:  # noqa: BLE001 - tracing is best-effort, never fatal
        return False
