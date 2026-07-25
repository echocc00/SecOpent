# src/secopent/domain/adapters/__init__.py
"""Adapter contracts package (§8.1 manifest, §8.3 Observation).

This package holds the four-domain common contract surface every Tool Adapter
must satisfy. The contract is stdlib-only (frozen dataclasses + StrEnum) so
the domain layer stays free of framework coupling; pydantic/SQLAlchemy live in
infrastructure.
"""
from __future__ import annotations
