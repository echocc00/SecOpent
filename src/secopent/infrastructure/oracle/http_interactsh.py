"""HttpInteractshTransport: real InteractshTransport over a self-hosted interactsh-server (W4-C T1).

The OOB callback channel (W3-E) is inert until a real transport backs
``InteractshClient``. This transport talks HTTP to a self-hosted
interactsh-server (deployed via ``scripts/provision/docker-compose.interactsh.yml``,
gated by ``SECOPTENT_INTERACTSH_SERVER_URL``).

Server contract (the server must expose, or be fronted by a thin adapter):
- ``POST {server_url}/register`` -> JSON with either ``correlation_domain`` OR
  both ``correlation_id`` + ``domain`` (composed as ``<correlation_id>.<domain>``).
- ``GET {server_url}/poll?id={correlation_domain}`` -> JSON list of interaction
  records. Each record is normalized to ``{unique_id, protocol, raw}`` from
  SecOpent's field names or interactsh-server's native ``unique-id`` /
  ``full-id`` / ``raw-request`` / ``raw-response``.

An injectable ``httpx.Client`` makes the transport unit-testable via
``httpx.MockTransport``; production leaves it ``None`` so each call uses a
short-lived client (no connection-pool lifecycle to manage).
"""
from __future__ import annotations

from typing import Any

import httpx


class HttpInteractshTransport:
    """InteractshTransport backed by HTTP calls to a self-hosted server."""

    def __init__(
        self,
        server_url: str,
        *,
        client: httpx.Client | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._url = server_url.rstrip("/")
        self._timeout = timeout
        self._client = client

    def register(self) -> str:
        data = self._request("POST", "/register", json={})
        if data.get("correlation_domain"):
            return str(data["correlation_domain"])
        cid = data.get("correlation_id")
        domain = data.get("domain")
        if cid and domain:
            return f"{cid}.{domain}"
        raise ValueError(
            f"interactsh register response missing correlation domain: {data}"
        )

    def poll(self, correlation_domain: str) -> list[dict[str, Any]]:
        data = self._request("GET", "/poll", params={"id": correlation_domain})
        records = data if isinstance(data, list) else data.get("interactions", [])
        return [self._normalize(r) for r in records if isinstance(r, dict)]

    def _request(self, method: str, path: str, **params: Any) -> Any:
        url = f"{self._url}{path}"
        if self._client is not None:
            resp = self._client.request(method, url, timeout=self._timeout, **params)
        else:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.request(method, url, **params)
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _normalize(record: dict[str, Any]) -> dict[str, Any]:
        return {
            "unique_id": str(
                record.get("unique_id")
                or record.get("unique-id")
                or record.get("full-id")
                or ""
            ),
            "protocol": str(record.get("protocol", "")),
            "raw": str(
                record.get("raw")
                or record.get("raw-request")
                or record.get("raw-response")
                or ""
            ),
        }
