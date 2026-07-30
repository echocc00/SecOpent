# tests/infrastructure/test_observability.py
"""Tests for Prometheus metrics, request-context logging, and tracing (T16)."""
from __future__ import annotations

import pytest
import structlog
from fastapi import FastAPI
from fastapi.testclient import TestClient
from structlog.testing import LogCapture

from secopent.infrastructure.observability import metrics as m
from secopent.infrastructure.observability.tracing import setup_tracing
from secopent.interfaces.api.main import create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


# --- /metrics endpoint -------------------------------------------------------


def test_metrics_endpoint_returns_prometheus_format(client: TestClient) -> None:
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    for family in (
        "secopent_assessments_total",
        "secopent_findings_total",
        "secopent_oracle_verification_seconds",
        "secopent_llm_tokens_total",
        "secopent_adapter_run_seconds",
    ):
        assert family in body


def test_metrics_served_under_api_subapp(client: TestClient) -> None:
    assert client.get("/api/metrics").status_code == 200


# --- metric recording --------------------------------------------------------


def test_record_finding_appears_in_metrics() -> None:
    m.record_finding(severity="high", oracle_verdict="confirmed", tenant="acme")
    out = m.render_metrics().decode()
    assert (
        'secopent_findings_total{oracle_verdict="confirmed",severity="high",'
        'tenant="acme"}' in out
    )


def test_record_assessment_appears_in_metrics() -> None:
    m.record_assessment(status="completed", tenant="acme")
    out = m.render_metrics().decode()
    assert 'secopent_assessments_total{status="completed",tenant="acme"}' in out


def test_adapter_timer_records() -> None:
    with m.time_adapter_run("nuclei"):
        pass
    assert 'adapter="nuclei"' in m.render_metrics().decode()


# --- request-context bound structured logging --------------------------------


def test_request_id_echoed_when_provided(client: TestClient) -> None:
    resp = client.get("/health", headers={"X-Request-Id": "req-123"})
    assert resp.headers.get("x-request-id") == "req-123"


def test_request_id_generated_when_absent(client: TestClient) -> None:
    assert client.get("/health").headers.get("x-request-id")


def test_structlog_merges_request_context() -> None:
    old = structlog.get_config()
    try:
        capture = LogCapture()
        structlog.configure(
            processors=[structlog.contextvars.merge_contextvars, capture]
        )
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id="rid-9", tenant="acme")
        structlog.get_logger().info("hello")
        entry = capture.entries[-1]
        assert entry["request_id"] == "rid-9"
        assert entry["tenant"] == "acme"
    finally:
        structlog.configure(**old)


# --- tracing safety ----------------------------------------------------------


def test_tracing_setup_is_a_safe_no_op_on_bare_app() -> None:
    assert isinstance(setup_tracing(FastAPI()), bool)
