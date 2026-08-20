# tests/e2e_real/test_ab_health.py
"""A/B target provisioning health check (v0.7.9 Task 1).

A trivial wiring check that the A/B acceptance harness's target map is wired:
``conftest._TARGETS`` adds the three A/B targets (Juice Shop, crAPI, vulhub) and
``_target_up`` can probe each one's front port. Each probe runs through
``require_target``, which SKIPS (never fails) when Docker is absent or the
target is unreachable — so this test only ever runs on a provisioned machine.

Marked ``integration``; because it exercises the ``require_target`` skip path,
it stays green (as a skip) in the default suite wherever Docker/targets are
absent.
"""
from __future__ import annotations

import pytest

# The three A/B comparison targets (spec §14.3 human decision gate).
_AB_TARGETS = ("juice_shop", "cr_api", "vulhub")


@pytest.mark.integration
def test_ab_targets_wired_and_probeable(require_target) -> None:  # type: ignore[no-untyped-def]
    """Each A/B target is registered and reachable (skips if not)."""
    for name in _AB_TARGETS:
        # ``require_target`` raises a skip (never a fail) when Docker is absent
        # or the named target's front port is down.
        require_target(name)
