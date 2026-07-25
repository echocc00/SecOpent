"""TDD tests for the OpenAPI/Postman importers (M3 Task 2, §11.9 documented path)."""
from __future__ import annotations

from secopent.domain.appmodel.lifecycle import AppModelStatus
from secopent.infrastructure.model_sources.openapi import OpenApiImporter
from secopent.infrastructure.model_sources.postman import PostmanImporter

_OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "Pet Store", "version": "1.2.3"},
    "paths": {
        "/pets": {
            "get": {
                "operationId": "listPets",
                "parameters": [
                    {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                ],
            },
            "post": {"operationId": "createPet"},
        },
        "/pets/{id}": {
            "delete": {"operationId": "deletePet"},
        },
    },
}

_SWAGGER2 = {
    "swagger": "2.0",
    "info": {"title": "Legacy", "version": "0.1.0"},
    "paths": {
        "/login": {
            "post": {
                "operationId": "login",
                "parameters": [{"name": "user", "in": "body", "type": "string"}],
            }
        }
    },
}

_POSTMAN = {
    "info": {"name": "Shop API", "version": "2.0.0"},
    "item": [
        {
            "name": "Auth",
            "item": [
                {
                    "name": "Login",
                    "request": {
                        "method": "POST",
                        "url": {"raw": "https://x/login", "path": ["login"]},
                    },
                }
            ],
        },
        {
            "name": "ListPets",
            "request": {"method": "GET", "url": {"raw": "https://x/pets", "path": ["pets"]}},
        },
    ],
}


def test_openapi_imports_transitions_and_fields() -> None:
    model = OpenApiImporter().to_draft(_OPENAPI)
    assert model.app_id == "pet-store"
    assert model.version == "1.2.3"
    assert model.status is AppModelStatus.DRAFT
    endpoints = {t.endpoint for t in model.transitions}
    assert endpoints == {"GET /pets", "POST /pets", "DELETE /pets/{id}"}
    # 'limit' parameter became a client-trusted int field.
    fields = {f.name: f for f in model.fields}
    assert fields["limit"].type == "int"
    assert fields["limit"].trusted_source == "client"


def test_openapi_transition_params_captured() -> None:
    model = OpenApiImporter().to_draft(_OPENAPI)
    list_pets = next(t for t in model.transitions if t.id == "listPets")
    assert list_pets.params == ("limit",)


def test_swagger2_inline_param_type() -> None:
    model = OpenApiImporter().to_draft(_SWAGGER2)
    fields = {f.name: f for f in model.fields}
    assert fields["user"].type == "str"
    assert {t.endpoint for t in model.transitions} == {"POST /login"}


def test_openapi_empty_paths() -> None:
    model = OpenApiImporter().to_draft({"info": {"title": "x", "version": "1"}, "paths": {}})
    assert model.transitions == ()


def test_postman_recurses_folders() -> None:
    model = PostmanImporter().to_draft(_POSTMAN)
    assert model.app_id == "shop-api"
    endpoints = {t.endpoint for t in model.transitions}
    # The nested folder request (Login) and the top-level one are both imported.
    assert endpoints == {"POST /login", "GET /pets"}
