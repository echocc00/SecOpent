# src/secopent/infrastructure/model_sources/postman.py
"""Postman v2.1 collection importer (§11.9 documented path).

Walks a Postman v2.1 collection (already loaded to a mapping), recursing through
nested folders (``item``), and turns each request into a Transition. The result
is a DRAFT AppModel a human enriches with states/invariants.
"""
from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from typing import Any

from secopent.domain.appmodel.models import AppModel, Transition


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "app"


def _path_from_url(url: Any) -> str:
    """Best-effort URL -> path string from a Postman url object/string."""
    if isinstance(url, str):
        return url
    if isinstance(url, Mapping):
        path = url.get("path")
        if isinstance(path, list):
            return "/" + "/".join(str(seg) for seg in path)
        raw = url.get("raw")
        if isinstance(raw, str):
            return raw
    return "/"


def _iter_requests(items: Any) -> Iterator[Mapping[str, Any]]:
    """Yield every request mapping, recursing into nested folders."""
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, Mapping):
            continue
        if isinstance(item.get("item"), list):
            yield from _iter_requests(item["item"])  # folder
        elif isinstance(item.get("request"), Mapping):
            yield item


class PostmanImporter:
    """Build a DRAFT AppModel from a Postman v2.1 collection mapping."""

    source_type = "postman"

    def to_draft(self, data: Mapping[str, Any]) -> AppModel:
        info = data.get("info") if isinstance(data.get("info"), Mapping) else {}
        name = str(info.get("name", "app"))
        version = str(info.get("version", "0.0.0"))

        transitions: list[Transition] = []
        for idx, item in enumerate(_iter_requests(data.get("item"))):
            request = item["request"]
            method = str(request.get("method", "GET")).upper()
            path = _path_from_url(request.get("url"))
            req_name = str(item.get("name") or f"request_{idx}")
            op_id = _slug(req_name) or f"request_{idx}"
            transitions.append(
                Transition(
                    id=op_id,
                    from_state="default",
                    to_state="default",
                    endpoint=f"{method} {path}",
                )
            )

        return AppModel(
            app_id=_slug(name),
            version=version,
            states=("default",),
            transitions=tuple(transitions),
        )
