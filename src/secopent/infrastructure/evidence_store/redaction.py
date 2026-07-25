# src/secopent/infrastructure/evidence_store/redaction.py
"""RedactionEngine: regex masking of secrets/PII in evidence (§13).

A curated regex library masks AWS keys, JWTs, private-key blocks, emails, CN
ID/mobile numbers, and internal IP addresses. Each match is classified by
``SecretOrigin``: a value present in ``ours_secrets`` (our canary token / own
credential) is OURS; anything else found on the target is TARGET (masked in
shared output but flaggable as evidence). The matched secret value itself is
never stored - only its ``kind`` and ``origin``.
"""
from __future__ import annotations

import re

from secopent.domain.evidence.models import Redaction, RedactionResult, SecretOrigin


class _Pattern:
    __slots__ = ("kind", "regex")

    def __init__(self, kind: str, regex: re.Pattern[str]) -> None:
        self.kind = kind
        self.regex = regex


def _compile(kind: str, pattern: str) -> _Pattern:
    return _Pattern(kind, re.compile(pattern))


# Ordered most-specific first so e.g. an 18-char CN ID is consumed before the
# 11-digit mobile pattern could match a substring of it.
_PATTERNS: tuple[_Pattern, ...] = (
    _compile(
        "private_key",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    ),
    _compile("jwt", r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    _compile("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
    _compile("cn_id", r"\b\d{17}[\dXx]\b"),
    _compile("cn_mobile", r"\b1[3-9]\d{9}\b"),
    _compile("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    _compile(
        "internal_ip",
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
    ),
)


class RedactionEngine:
    """Mask secrets/PII in text, classifying each redaction by origin."""

    def __init__(self, ours_secrets: frozenset[str] = frozenset()) -> None:
        self._ours = set(ours_secrets)

    def redact(self, text: str) -> RedactionResult:
        """Return a RedactionResult with all secret/PII spans masked."""
        redactions: list[Redaction] = []
        current = text
        for pattern in _PATTERNS:
            def _repl(match: re.Match[str], _kind: str = pattern.kind) -> str:
                origin = (
                    SecretOrigin.OURS
                    if match.group(0) in self._ours
                    else SecretOrigin.TARGET
                )
                redactions.append(Redaction(kind=_kind, origin=origin))
                return f"[REDACTED:{_kind}]"

            current = pattern.regex.sub(_repl, current)
        return RedactionResult(redacted_text=current, redactions=tuple(redactions))
