# src/secopent/infrastructure/oracle/diff_semantic_runner.py
"""DiffSemanticRunner: HTTP(S) transport for the DIFF_SEMANTIC oracle (v0.7.6).

The DIFF_SEMANTIC oracle confirms a finding by executing a baseline request and
an assertion request against the target and comparing observable differences
(HTTP status / response body). This module is the *pure infrastructure
transport*: it executes ONE request dict over HTTP(S) and returns a normalized
:class:`DiffSemanticResponse`. It decides nothing - the domain
``decide_diff_outcome`` (Task 2) consumes the status/body/error and makes the
semantic decision.

Design:
- :class:`DiffSemanticRunner` is a ``runtime_checkable`` Protocol so the
  application/verifier tiers depend only on the transport surface.
- ``with_session`` lets the worker reuse a shared session across many
  executions without holding a long-lived client (immutable-ish swap).
- httpx is used (already a project dependency, ``httpx>=0.27,<1.0``); the
  injected session is duck-typed so tests supply a fake and no network is used.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

import httpx


@dataclass(frozen=True, slots=True)
class DiffSemanticResponse:
    """Normalized result of executing one HTTP(S) request.

    ``status`` is the HTTP status (or 0 on transport/request error -> the
    downstream SERVER_ERROR signal). ``body`` is the parsed JSON dict body when
    the response is JSON, else None. ``error`` carries the transport error text
    (empty on success).
    """

    status: int
    body: dict[str, object] | None = None
    error: str = ""


@runtime_checkable
class DiffSemanticRunner(Protocol):
    """The transport surface consumed by the DIFF_SEMANTIC oracle tiers.

    ``with_session`` is an *optional* capability (some fakes may not implement
    it); callers that need it detect it via ``hasattr`` / isinstance. The real
    transport MUST provide it, and it is declared here so the verifier task can
    depend on it.
    """

    def execute(self, request: dict[str, object]) -> DiffSemanticResponse: ...

    def with_session(self, session: object) -> DiffSemanticRunner: ...


class HttpDiffSemanticRunner:
    """Concrete httpx-backed transport for one request dict."""

    def __init__(
        self,
        session: object | None = None,
        *,
        timeout: float = 10.0,
        allow_redirects: bool = False,
    ) -> None:
        self._timeout = timeout
        self._allow_redirects = allow_redirects
        if session is None:
            self._session: Any = httpx.Client(
                timeout=timeout, follow_redirects=allow_redirects
            )
        else:
            self._session = session

    def with_session(self, session: object) -> HttpDiffSemanticRunner:
        """Return a runner bound to a different session (worker reuse)."""
        return HttpDiffSemanticRunner(
            session=session,
            timeout=self._timeout,
            allow_redirects=self._allow_redirects,
        )

    def execute(self, request: dict[str, object]) -> DiffSemanticResponse:
        try:
            method = str(request.get("method", "GET")).upper()
            url = request.get("url")
            if url is None or not isinstance(url, str) or not url:
                raise ValueError("request 'url' must be a non-empty string")
            headers: dict[str, str] | None = None
            raw_headers = request.get("headers")
            if isinstance(raw_headers, dict):
                headers = {
                    str(k): str(v) for k, v in raw_headers.items()
                }

            kwargs: dict[str, Any] = {}
            body = request.get("body")
            if isinstance(body, dict):
                kwargs["json"] = body
            elif isinstance(body, str):
                kwargs["content"] = body

            resp = self._session.request(
                method, url, headers=headers, **kwargs
            )

            status_raw: object = getattr(resp, "status_code", None)
            if status_raw is None:
                status_raw = getattr(resp, "status", 0)
            status = status_raw if isinstance(status_raw, int) else 0

            body_parsed: dict[str, object] | None = None
            content_type = ""
            for key, value in getattr(resp, "headers", {}).items():
                if str(key).lower() == "content-type":
                    content_type = str(value)
            if "json" in content_type.lower():
                try:
                    parsed = resp.json()
                    if isinstance(parsed, dict):
                        body_parsed = {str(k): v for k, v in parsed.items()}
                except Exception:
                    body_parsed = None
            return DiffSemanticResponse(status=status, body=body_parsed)
        except Exception as exc:  # transport/request error -> SERVER_ERROR signal
            return DiffSemanticResponse(status=0, error=str(exc))
