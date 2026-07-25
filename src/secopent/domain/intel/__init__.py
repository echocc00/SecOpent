# src/secopent/domain/intel/__init__.py
"""Intel domain entities (vulnerabilities, affected products, signals, mappings).

This package captures the platform's read-only knowledge layer for security
intelligence. Every external-sourced field carries a `Provenance` record so the
platform never silently overwrites one source's reading with another's (see
main design §10.7).
"""
from __future__ import annotations
