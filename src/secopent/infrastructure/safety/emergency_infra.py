# src/secopent/infrastructure/safety/emergency_infra.py
"""Infrastructure for the emergency stop (§12): container terminator + permit revoker.

These satisfy the application-layer ``ContainerTerminator`` / ``PermitRevoker``
protocols so ``EmergencyStop`` can act on the real environment:

- ``DockerContainerTerminator`` stops running execution containers (labelled
  ``secopent``) via the Docker CLI; returns 0 when Docker is unavailable or no
  containers are running (honest count).
- ``NullPermitRevoker`` is a placeholder: permits are short-lived signed tokens
  not persisted in a revocable store yet, so there is nothing to revoke (0).
  A revocable permit store is a follow-up (P4 remote worker).
"""
from __future__ import annotations

import subprocess


class DockerContainerTerminator:
    """Terminate running secopent execution containers via the Docker CLI."""

    def __init__(self, label_filter: str = "secopent") -> None:
        self._label_filter = label_filter

    def terminate_active(self) -> int:
        try:
            listed = subprocess.run(
                ["docker", "ps", "-q", "--filter", f"label={self._label_filter}"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return 0
        ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
        if not ids:
            return 0
        stopped = subprocess.run(
            ["docker", "stop", *ids],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        return len([line for line in stopped.stdout.splitlines() if line.strip()])


class NullPermitRevoker:
    """Placeholder revoker: no revocable permit store is wired yet (returns 0)."""

    def revoke_unused(self) -> int:
        return 0
