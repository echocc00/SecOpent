# src/secopent/infrastructure/logging_setup.py
"""Structured logging (§3.8): JSON/console logs with sensitive-field redaction.

Configures structlog so every log record is structured (JSON in production via
SECOPTENT_LOG_FORMAT=json, console otherwise) and sensitive keys (secrets,
tokens, signatures) are redacted before rendering - no secret material reaches
the logs.
"""
from __future__ import annotations

import structlog
from structlog.typing import EventDict, Processor, WrappedLogger

_SENSITIVE = {
    "password",
    "secret",
    "token",
    "api_key",
    "authorization",
    "cookie",
    "signature",
    "private_key",
}


def _redact_processor(
    _logger: WrappedLogger, _method_name: str, event_dict: EventDict
) -> EventDict:
    for key in list(event_dict):
        if key.lower() in _SENSITIVE:
            event_dict[key] = "[REDACTED]"
    return event_dict


def configure_logging(*, json_format: bool = False) -> None:
    """Configure structlog (idempotent). JSON renderer when ``json_format``."""
    renderer: Processor = (
        structlog.processors.JSONRenderer()
        if json_format
        else structlog.dev.ConsoleRenderer()
    )
    processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        _redact_processor,
        structlog.processors.TimeStamper(fmt="iso"),
        renderer,
    ]
    structlog.configure(processors=processors)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]
