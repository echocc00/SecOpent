"""Peer agent infrastructure: container harness for external pentest agents.

This package provides the runtime shell that executes peer agents (Strix,
Shannon, ...) inside hardened Docker containers, reusing the same hardening
flags as tool adapters (digest pinning, non-root, cap-drop ALL, read-only
rootfs, resource limits, bridge network). P0 ships the contract and fake
tests; real backends land with P2 (Strix) and P3 (Shannon).
"""
