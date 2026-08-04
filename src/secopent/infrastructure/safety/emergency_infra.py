# src/secopent/infrastructure/safety/emergency_infra.py
"""Infrastructure for the emergency stop (§12): container terminator + permit revoker.

These satisfy the application-layer ``ContainerTerminator`` / ``PermitRevoker``
protocols so ``EmergencyStop`` can act on the real environment:

- ``DockerContainerTerminator`` stops running execution containers (labelled
  ``secopent=execution``) via the Docker CLI. Raises ``DockerUnreachableError``
  when the daemon cannot be contacted - an emergency stop MUST fail loudly
  rather than silently report success.
- ``NullPermitRevoker`` is the no-op fallback for tests/legacy paths: production
  wires ``InMemoryPermitRevoker`` (``infrastructure/safety/permit_revoker.py``)
  in the composition root so permits ARE persisted in a revocable store. Keep
  NullPermitRevoker for unit tests that exercise EmergencyStop in isolation.
"""
from __future__ import annotations

import subprocess


class DockerUnreachableError(RuntimeError):
    """The Docker daemon is not reachable; emergency stop cannot verify termination."""


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
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DockerUnreachableError(
                f"cannot reach Docker daemon during emergency stop: {exc}"
            ) from exc
        if listed.returncode != 0:
            raise DockerUnreachableError(
                f"docker ps failed (exit {listed.returncode}): {listed.stderr.strip()}"
            )
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


class NullContainerTerminator:
    """No-op terminator: terminates nothing, returns 0.

    Used in tests and non-Docker environments (e.g. Windows dev hosts) where
    container termination is neither possible nor required.
    """

    def terminate_active(self) -> int:
        return 0


class NullPermitRevoker:
    """Placeholder revoker: no revocable permit store is wired yet (returns 0)."""

    def revoke_unused(self) -> int:
        return 0
