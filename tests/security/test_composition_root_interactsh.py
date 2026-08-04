"""Interactsh transport selection in composition root (W4-C T3)."""
from __future__ import annotations

import pytest

from secopent.infrastructure.db.sqlite import create_sqlite_engine
from secopent.infrastructure.oracle.http_interactsh import HttpInteractshTransport
from secopent.infrastructure.oracle.null_interactsh import NullInteractshTransport
from secopent.interfaces.api.main import create_app


def _transport(app) -> object:  # type: ignore[no-untyped-def]
    return app.state.oracle._verifier_factory._interactsh._transport


def test_null_transport_when_no_server_url(tmp_path) -> None:  # type: ignore[no-untyped-def]
    app = create_app(engine=create_sqlite_engine(tmp_path / "w4c3.db"))
    assert isinstance(_transport(app), NullInteractshTransport)


def test_http_transport_when_server_url_set(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("SECOPTENT_INTERACTSH_SERVER_URL", "http://oast.test")
    app = create_app(engine=create_sqlite_engine(tmp_path / "w4c3.db"))
    assert isinstance(_transport(app), HttpInteractshTransport)
