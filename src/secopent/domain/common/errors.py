# src/secopent/domain/common/errors.py
from __future__ import annotations


class DomainError(Exception):
    """Base deterministic domain error."""


class DomainValidationError(DomainError, ValueError):
    """Input cannot be normalized safely."""
