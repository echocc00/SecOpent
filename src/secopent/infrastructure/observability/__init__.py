# src/secopent/infrastructure/observability/
"""Observability (T16 / cross-cutting §③): Prometheus metrics, request-context
bound structured logging, and best-effort OpenTelemetry tracing.

- ``metrics``: five application metric families + ``/metrics`` rendering.
- ``context``: per-request ``request_id``/``tenant`` bound into structlog.
- ``tracing``: optional FastAPI auto-instrumentation (degrades to a no-op).
"""
