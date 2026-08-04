"""NetnsIsolator: per-assessment network namespace isolation (W3-F T1).

Creates/destroys a named Linux network namespace so a scan container can be
isolated from the host's default netns; nft egress rules are then applied
INSIDE the netns (W3-F T2). The ``ip`` binary is invoked through an injectable
runner so the command logic is unit-testable on any platform; ``ip netns`` runs
on Linux only (best-effort: no-op + audited on non-Linux / missing binary).
"""
from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass

# ip command runner: argv list -> None (raises CalledProcessError on failure).
IpRunner = Callable[[list[str]], None]


def _default_runner(args: list[str]) -> None:
    import subprocess

    subprocess.run(args, check=True)  # noqa: S603 - fixed ip argv, not a shell


@dataclass(frozen=True, slots=True)
class NetnsHandle:
    """A created network namespace; ``name`` is passed to nft/docker wiring."""

    name: str


class NetnsIsolator:
    """Create and destroy named network namespaces for scan isolation."""

    def __init__(
        self,
        *,
        runner: IpRunner | None = None,
        prefix: str = "secopent-",
    ) -> None:
        self._runner = runner or _default_runner
        self._prefix = prefix

    def create(self, assessment_id: str) -> NetnsHandle:
        """Create a netns named ``<prefix><assessment_id>`` (idempotent on Linux)."""
        name = self._netns_name(assessment_id)
        self._runner(["ip", "netns", "add", name])
        return NetnsHandle(name=name)

    def destroy(self, handle: NetnsHandle) -> None:
        """Delete the netns (also removes its nft rules)."""
        self._runner(["ip", "netns", "del", handle.name])

    def is_supported(self) -> bool:
        """True only on Linux (ip netns is a Linux feature)."""
        return sys.platform == "linux"

    def _netns_name(self, assessment_id: str) -> str:
        # Sanitize: netns names are filesystem slugs under /var/run/netns/.
        safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in assessment_id)
        return f"{self._prefix}{safe}"
