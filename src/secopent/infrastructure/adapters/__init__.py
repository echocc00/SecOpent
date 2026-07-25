"""Adapter execution infrastructure (M1 Task 8).

This package contains the concrete runner that turns an `AdapterManifest`
plus an `AdapterInput` into a normalized `AdapterOutput` while enforcing the
M0 scope gate (via `PolicyEngine.evaluate`) BEFORE any container is invoked,
and the container-security envelope (§8.4 Scoped Egress) once execution is
authorized.
"""
