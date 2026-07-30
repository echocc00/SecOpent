# src/secopent/interfaces/api/messages.py
"""Backend error-message localization by Accept-Language (T14 / cross-cutting §⑥).

A minimal i18n layer for API error responses: stable message keys map to zh/en
strings, and the locale is parsed from the ``Accept-Language`` header (default
zh-CN, matching the frontend). Call sites opt in by resolving a key with
:func:`localize` and the :func:`get_locale` dependency; remaining error sites
migrate to keys incrementally (free-text ``detail=`` strings still work).
"""
from __future__ import annotations

from fastapi import Request

# Stable message key -> {"zh": ..., "en": ...}.
MESSAGES: dict[str, dict[str, str]] = {
    "assessment.not_found": {"zh": "评估不存在", "en": "assessment not found"},
    "scope.not_found": {"zh": "范围快照不存在", "en": "scope snapshot not found"},
    "common.forbidden": {"zh": "禁止访问", "en": "forbidden"},
    "common.not_found": {"zh": "资源不存在", "en": "not found"},
}

DEFAULT_LANG = "zh"


def parse_accept_language(header: str | None) -> str:
    """Pick the best supported language from an ``Accept-Language`` header.

    Ranks entries by q-value and returns the first supported tag; defaults to
    zh-CN. Robust to malformed input (unknown/empty headers yield the default).
    """
    if not header:
        return DEFAULT_LANG
    ranked: list[tuple[float, str]] = []
    for part in header.split(","):
        token, _, params = part.partition(";")
        tag = token.strip().lower()
        quality = 1.0
        if params.strip().startswith("q="):
            try:
                quality = float(params.strip()[2:])
            except ValueError:
                quality = 0.0
        ranked.append((quality, tag))
    ranked.sort(key=lambda item: item[0], reverse=True)
    for _, tag in ranked:
        if tag.startswith("en"):
            return "en"
        if tag.startswith("zh"):
            return "zh"
    return DEFAULT_LANG


def localize(key: str, lang: str | None, **fmt: object) -> str:
    """Resolve a message key to the localized string (falls back to en, then key)."""
    entry = MESSAGES.get(key)
    if entry is None:
        return key
    resolved = entry.get(lang or DEFAULT_LANG) or entry.get("en") or key
    return resolved.format(**fmt) if fmt else resolved


def get_locale(request: Request) -> str:
    """FastAPI dependency: the request's preferred supported language."""
    return parse_accept_language(request.headers.get("accept-language"))
