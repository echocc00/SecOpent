# src/secopent/infrastructure/model_sources/openapi.py
"""OpenAPI 3.x / Swagger 2.0 importer (§11.9 documented path).

Parses an OpenAPI/Swagger spec (already loaded to a mapping) into a DRAFT
AppModel: each (path, method) operation becomes a Transition; each parameter
becomes a client-trusted Field. The result is a DRAFT - OpenAPI has no notion of
business states/invariants, so a human enriches those in the validation step.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from secopent.domain.appmodel.models import AppModel, Field, Transition

_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}

# OpenAPI type -> AppModel field type.
_TYPE_MAP = {
    "integer": "int",
    "number": "float",
    "string": "str",
    "boolean": "bool",
    "array": "list",
    "object": "dict",
}


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "app"


def _param_type(param: Mapping[str, Any]) -> str:
    schema = param.get("schema")
    raw = ""
    if isinstance(schema, Mapping):
        raw = str(schema.get("type", ""))
    if not raw:
        raw = str(param.get("type", ""))  # Swagger 2.0 inline type
    return _TYPE_MAP.get(raw, "str")


class OpenApiImporter:
    """Build a DRAFT AppModel from an OpenAPI/Swagger spec mapping."""

    source_type = "openapi"

    def to_draft(self, data: Mapping[str, Any]) -> AppModel:
        info_raw = data.get("info")
        info: Mapping[str, Any] = info_raw if isinstance(info_raw, Mapping) else {}
        title = str(info.get("title", "app"))
        version = str(info.get("version", "0.0.0"))
        paths = data.get("paths")
        paths = paths if isinstance(paths, Mapping) else {}

        transitions: list[Transition] = []
        fields: list[Field] = []
        seen_fields: set[str] = set()

        for path, methods in paths.items():
            if not isinstance(methods, Mapping):
                continue
            for method, operation in methods.items():
                if method.lower() not in _HTTP_METHODS:
                    continue
                if not isinstance(operation, Mapping):
                    continue
                op_id = str(operation.get("operationId") or f"{method.lower()}{path}")
                params = operation.get("parameters")
                params = params if isinstance(params, list) else []
                param_names: list[str] = []
                for param in params:
                    if not isinstance(param, Mapping):
                        continue
                    name = param.get("name")
                    if not isinstance(name, str) or not name:
                        continue
                    param_names.append(name)
                    if name not in seen_fields:
                        seen_fields.add(name)
                        fields.append(
                            Field(
                                name=name,
                                type=_param_type(param),
                                trusted_source="client",
                            )
                        )
                transitions.append(
                    Transition(
                        id=op_id,
                        from_state="default",
                        to_state="default",
                        endpoint=f"{method.upper()} {path}",
                        params=tuple(param_names),
                    )
                )

        return AppModel(
            app_id=_slug(title),
            version=version,
            states=("default",),
            transitions=tuple(transitions),
            fields=tuple(fields),
        )
