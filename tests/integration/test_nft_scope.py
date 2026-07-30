# tests/integration/test_nft_scope.py
"""Live nftables scoped-egress integration test (P2-G / M5, Linux only).

Loads ``scripts/provision/egress.nft`` and drives ``NftScopeEnforcer`` with the
REAL ``nft`` binary + system resolver, then asserts the kernel sets actually
contain the expected elements:

- a malicious scope (cloud-metadata 169.254.169.254) lands in ``blocked_targets``
  and NEVER in ``allowed_targets`` (the output chain drops it);
- an in-scope public IP lands in ``allowed_targets``;
- ``revoke()`` flushes both sets.

Requires ``nft`` and root (CAP_NET_ADMIN); skipped elsewhere (e.g. Windows, or a
non-privileged checkout). The CI ``egress`` job runs it on an ubuntu runner.
"""
from __future__ import annotations

import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from secopent.domain.scope.models import ScopeLimits, ScopeSnapshot
from secopent.infrastructure.egress.nft_scope import NftScopeEnforcer, SocketDnsResolver

_TABLE = "secopent_egress"
_EGRESS_NFT = Path(__file__).parents[2] / "scripts" / "provision" / "egress.nft"


def _can_use_nft() -> bool:
    if shutil.which("nft") is None:
        return False
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv
            ["nft", "list", "tables"], capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0  # non-zero => missing CAP_NET_ADMIN / not root


def _snapshot(include: tuple[str, ...]) -> ScopeSnapshot:
    return ScopeSnapshot(
        id="snap-nft",
        project_id="proj-1",
        include=include,
        exclude=(),
        ports=(443,),
        limits=ScopeLimits(requests_per_second=5.0, concurrency=3, max_requests=50_000),
        approved_by="analyst",
        approved_at=datetime(2026, 1, 1, tzinfo=UTC),
        digest="sha256:" + "0" * 64,
    )


def _set_elements(set_name: str) -> str:
    proc = subprocess.run(  # noqa: S603 - fixed argv
        ["nft", "list", "set", "inet", _TABLE, set_name],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    return proc.stdout


@pytest.mark.integration
def test_nft_scoped_egress_blocks_metadata_and_allows_scope() -> None:
    if not _can_use_nft():
        pytest.skip("nft unavailable or insufficient privileges (needs root/CAP_NET_ADMIN)")

    subprocess.run(["nft", "-f", str(_EGRESS_NFT)], check=True, timeout=30)  # noqa: S603
    try:
        enforcer = NftScopeEnforcer(SocketDnsResolver())
        result = enforcer.apply_scope(
            _snapshot(("169.254.169.254", "8.8.8.8"))
        )

        # Metadata IP is denied + blocked, never allowed.
        assert "169.254.169.254" in result.blocked
        assert "169.254.169.254" not in result.allowed
        # Public in-scope IP is allowed.
        assert "8.8.8.8" in result.allowed

        blocked = _set_elements("blocked_targets")
        allowed = _set_elements("allowed_targets")
        assert "169.254" in blocked
        assert "8.8.8.8" in allowed
        assert "8.8.8.8" not in blocked

        # revoke flushes both sets.
        enforcer.revoke()
        assert "8.8.8.8" not in _set_elements("allowed_targets")
    finally:
        subprocess.run(  # noqa: S603 - best-effort teardown
            ["nft", "delete", "table", "inet", _TABLE], check=False, timeout=30
        )
