"""NetnsIsolator: per-assessment network namespace isolation (W3-F T1).

Creates/destroys a named Linux network namespace so a scan container can be
isolated from the host's default netns; nft egress rules are then applied
INSIDE the netns (W3-F T2). The ``ip`` command is invoked through an injectable
runner so the command logic is unit-testable on any platform; ``ip netns`` runs
on Linux only (best-effort: no-op + audited on non-Linux / missing binary).

Phase 2.3 (方案 A): ``create()`` additionally starts a **sidecar container**
(``alpine sleep infinity``) whose network namespace is moved into the named
netns. Scan containers then join the sidecar's network namespace via
``docker run --network=container:<sidecar>`` rather than the Docker bridge.
This is the recommended approach because the Docker daemon itself does not run
inside a netns, so ``nsenter``-based approaches are fragile. ``destroy()``
removes both the sidecar container and the netns.

v0.5.1 F1 (NAS incident): ``is_supported()`` no longer trusts ``sys.platform``
alone - restricted Linux kernels (UGREEN/Synology/QNAP NAS) report Linux but
lack full ``ip netns`` support. It now probes ``ip netns add/del`` once
(cached) and honors ``SECOPTENT_NETNS_ENABLED=0`` to force it off. v0.5.1 F3:
``create()`` self-cleans on partial failure so a half-bound sidecar/netns pair
is never left behind (the caller can only destroy a returned handle).
"""
from __future__ import annotations

import contextlib
import logging
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass

_logger = logging.getLogger(__name__)

# Command runner: argv list -> None (raises CalledProcessError on failure).
# Used for both ``ip`` and ``docker`` invocations (Phase 2.3 sidecar).
IpRunner = Callable[[list[str]], None]


def _default_runner(args: list[str]) -> None:
    import subprocess

    subprocess.run(args, check=True)  # noqa: S603 - fixed argv, not a shell


@dataclass(frozen=True, slots=True)
class NetnsHandle:
    """A created network namespace + its bound sidecar container.

    ``name`` is the named netns (passed to nft wiring). ``sidecar`` is the
    Docker container name scan containers join via
    ``--network=container:<sidecar>``. ``sidecar`` is empty when sidecar
    binding is disabled (``with_sidecar=False``).
    """

    name: str
    sidecar: str = ""


class NetnsIsolator:
    """Create and destroy named network namespaces for scan isolation.

    Phase 2.3 (方案 A): by default ``create()`` also starts a sidecar
    container bound to the netns so scan containers can share its network
    namespace. Set ``with_sidecar=False`` to get the legacy behaviour
    (netns only, no sidecar - useful when the caller manages its own
    container-to-netns binding).
    """

    # The sidecar image: a tiny no-op container that just sleeps. It exists
    # solely to hold a network namespace the scan containers join; it runs no
    # tooling. alpine is already pulled by the integration tests.
    _SIDECAR_IMAGE = "alpine"
    _SIDECAR_COMMAND = ["sleep", "infinity"]

    def __init__(
        self,
        *,
        runner: IpRunner | None = None,
        prefix: str = "secopent-",
        sidecar_prefix: str = "secopent-netns-",
    ) -> None:
        self._runner = runner or _default_runner
        self._prefix = prefix
        self._sidecar_prefix = sidecar_prefix
        # v0.5.1 F1: one-shot capability-probe result (None = not yet probed).
        self._capability_cache: bool | None = None

    def create(
        self, assessment_id: str, *, with_sidecar: bool = True
    ) -> NetnsHandle:
        """Create a netns named ``<prefix><assessment_id>``.

        ``ip netns add`` FAILS if a netns with the same name already exists -
        it is not idempotent. When ``with_sidecar`` is True (default,
        Phase 2.3), additionally start a sidecar container
        ``<sidecar_prefix><assessment_id>`` with ``--network=none`` and move
        its network namespace into the named netns. The returned handle
        carries the sidecar name so callers can wire
        ``--network=container:<sidecar>`` on scan containers.

        v0.5.1 F3: if any step after the netns is created fails, the
        half-bound sidecar container + netns are torn down before re-raising
        - the caller can only destroy a returned handle, so create() must
        never leave residue behind.
        """
        name = self._netns_name(assessment_id)
        self._runner(["ip", "netns", "add", name])
        if not with_sidecar:
            return NetnsHandle(name=name, sidecar="")
        sidecar = self._sidecar_name(assessment_id)
        try:
            # Start sidecar with --network=none so it has an isolated, empty netns
            # we then relocate into the named netns. --network=none also prevents
            # the sidecar from getting a bridge IP (it needs no network of its own;
            # the scan containers sharing its netns get their IPs/egress policy
            # from the named netns + nft rules).
            self._runner(
                [
                    "docker", "run", "-d", "--name", sidecar,
                    "--network=none", "--restart=no",
                    self._SIDECAR_IMAGE, *self._SIDECAR_COMMAND,
                ]
            )
            # Move the sidecar's netns into the named netns. The sidecar's PID
            # identifies its current netns; ``ip netns attach <name> <pid>`` makes
            # the named netns refer to that same namespace. (Equivalent to the
            # symlink approach: ln -s /proc/<pid>/ns/net /var/run/netns/<name>.)
            pid = self._inspect_sidecar_pid(sidecar)
            self._runner(["ip", "netns", "attach", name, pid])
        except Exception:
            # F3: roll back whatever we created before failing.
            with contextlib.suppress(Exception):
                self._runner(["docker", "rm", "-f", sidecar])
            with contextlib.suppress(Exception):
                self._runner(["ip", "netns", "del", name])
            raise
        return NetnsHandle(name=name, sidecar=sidecar)

    def destroy(self, handle: NetnsHandle) -> None:
        """Delete the netns and stop/remove the sidecar container if present.

        The sidecar is removed first so its network namespace is released
        before the named netns is deleted (avoids a dangling ns reference).
        ``docker rm -f`` is idempotent (no error if the container is gone).
        """
        if handle.sidecar:
            self._runner(["docker", "rm", "-f", handle.sidecar])
        self._runner(["ip", "netns", "del", handle.name])

    def is_supported(self) -> bool:
        """True only on Linux WITH a usable ``ip netns`` (probe, cached).

        v0.5.1 F1: ``sys.platform == "linux"`` alone is not enough - restricted
        NAS kernels (UGREEN/Synology/QNAP) report Linux but lack full iproute2
        netns support. The first call probes ``ip netns add/del`` once and
        caches the result. ``SECOPTENT_NETNS_ENABLED=0`` forces the probe off.
        """
        if sys.platform != "linux":
            return False
        if os.environ.get("SECOPTENT_NETNS_ENABLED", "1").lower() in {
            "0", "false", "no",
        }:
            return False
        if self._capability_cache is None:
            self._capability_cache = self._probe_capability()
        return self._capability_cache

    def _probe_capability(self) -> bool:
        """One-shot probe: can ``ip netns add/del`` actually run on this host?"""
        import subprocess

        probe = f"{self._prefix}probe"
        try:
            result = subprocess.run(
                ["ip", "netns", "add", probe], capture_output=True, timeout=5
            )
            if result.returncode != 0:
                _logger.warning(
                    "netns capability probe failed: ip netns add returned %s "
                    "(assessment egress isolation will degrade to the default netns)",
                    result.returncode,
                )
                return False
            subprocess.run(
                ["ip", "netns", "del", probe], capture_output=True, timeout=5
            )
            return True
        except (OSError, subprocess.SubprocessError) as exc:
            _logger.warning(
                "netns capability probe unavailable: %s "
                "(assessment egress isolation will degrade to the default netns)",
                exc,
            )
            return False

    def _netns_name(self, assessment_id: str) -> str:
        # Sanitize: netns names are filesystem slugs under /var/run/netns/.
        safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in assessment_id)
        return f"{self._prefix}{safe}"

    def _sidecar_name(self, assessment_id: str) -> str:
        # Same sanitization as the netns name; container names share the slug
        # charset. Keeping the two names distinct (different prefixes) makes
        # `docker ps` / `ip netns list` output unambiguous.
        safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in assessment_id)
        return f"{self._sidecar_prefix}{safe}"

    def _inspect_sidecar_pid(self, sidecar: str) -> str:
        """Return the sidecar container's PID as a string.

        Uses ``docker inspect -f '{{.State.Pid}}' <sidecar>``. Executed through
        the injectable runner would lose the stdout capture (the runner
        signature is argv -> None), so this uses ``subprocess.check_output``
        directly. The runner is still used for all the side-effectful
        create/destroy commands; PID inspection is a read-only query.
        """
        import subprocess

        return subprocess.check_output(  # noqa: S603 - fixed argv, not a shell
            ["docker", "inspect", "-f", "{{.State.Pid}}", sidecar],
            encoding="utf-8",
        ).strip()
