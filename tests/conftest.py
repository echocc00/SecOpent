"""Project-wide test fixtures.

Every test gets an isolated SQLite DB via SECOPTENT_DB_URL so ``create_app()``
(without an explicit engine) does not write to the host filesystem and tests do
not pollute each other. Tests that need to assert on the env-unset path
(``test_db_engine``) override this with their own ``monkeypatch``.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_db_url(tmp_path: pytest.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point SECOPTENT_DB_URL at a per-test tmp DB (isolation + no host pollution)."""
    monkeypatch.setenv("SECOPTENT_DB_URL", f"sqlite:///{tmp_path / 'test.db'}")
