# src/secopent/infrastructure/sandbox/case_context.py
"""CaseContext SDK: the only surface a Python plugin may use (§11.4).

A plugin running in the sandbox cannot touch the host directly - it reaches the
world solely through the declarative capabilities granted on this context:
``scoped_http`` / ``scoped_tcp`` (scope-bounded network), ``oast`` (out-of-band
callback allocation), ``credential_ref`` (a reference handle, never the raw
secret), ``temp_fs`` (an isolated scratch dir), and ``emit_observation`` (the
only way to report a finding). Anything else (subprocess, raw sockets, host FS,
DB, dynamic import) is unavailable because it is simply not exposed here.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from secopent.domain.common.errors import DomainError


class CapabilityNotGranted(DomainError):
    """Raised when a plugin uses a capability that was not granted to it."""


class CaseContext:
    """Declarative capability surface handed to a sandboxed plugin."""

    def __init__(
        self,
        *,
        http: Callable[..., Any] | None = None,
        tcp: Callable[..., Any] | None = None,
        oast: Callable[[], str] | None = None,
        credentials: dict[str, str] | None = None,
        temp_dir: str = "",
    ) -> None:
        self._http = http
        self._tcp = tcp
        self._oast = oast
        self._credentials = dict(credentials or {})
        self._temp_dir = temp_dir
        self.observations: list[dict[str, Any]] = []

    def scoped_http(self, method: str, url: str, **kwargs: Any) -> Any:
        if self._http is None:
            raise CapabilityNotGranted("scoped_http capability not granted")
        return self._http(method=method, url=url, **kwargs)

    def scoped_tcp(self, host: str, port: int) -> Any:
        if self._tcp is None:
            raise CapabilityNotGranted("scoped_tcp capability not granted")
        return self._tcp(host=host, port=port)

    def oast(self) -> str:
        if self._oast is None:
            raise CapabilityNotGranted("oast capability not granted")
        return self._oast()

    def credential_ref(self, name: str) -> str:
        """Return an opaque reference handle - never the raw secret value."""
        if name not in self._credentials:
            raise CapabilityNotGranted(f"credential not granted: {name}")
        return f"credential-ref:{name}"

    def temp_fs(self) -> str:
        return self._temp_dir

    def emit_observation(self, **fields: Any) -> None:
        self.observations.append(dict(fields))
