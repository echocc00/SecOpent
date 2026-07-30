# tests/interfaces/test_api_i18n.py
"""Backend Accept-Language error localization (T14 / cross-cutting §⑥)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from secopent.interfaces.api.main import create_app
from secopent.interfaces.api.messages import localize, parse_accept_language


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


# --- parse_accept_language ---------------------------------------------------


def test_parse_accept_language_defaults_to_zh() -> None:
    assert parse_accept_language(None) == "zh"
    assert parse_accept_language("") == "zh"
    # Unsupported languages fall back to the zh-CN default.
    assert parse_accept_language("fr-FR,de;q=0.9") == "zh"


def test_parse_accept_language_english() -> None:
    assert parse_accept_language("en-US,en;q=0.9") == "en"
    assert parse_accept_language("en") == "en"


def test_parse_accept_language_zh() -> None:
    assert parse_accept_language("zh-CN,zh;q=0.9") == "zh"


def test_parse_accept_language_respects_q_ordering() -> None:
    assert parse_accept_language("zh;q=0.5,en;q=0.9") == "en"


# --- localize ----------------------------------------------------------------


def test_localize_known_key_both_langs() -> None:
    assert localize("assessment.not_found", "en") == "assessment not found"
    assert localize("assessment.not_found", "zh") == "评估不存在"


def test_localize_unknown_key_returns_key() -> None:
    assert localize("nope.missing", "en") == "nope.missing"


def test_localize_defaults_when_lang_none() -> None:
    assert localize("assessment.not_found", None) == "评估不存在"


# --- end-to-end via the Accept-Language header -------------------------------


def test_approval_404_detail_localized_en(client: TestClient) -> None:
    resp = client.post(
        "/approvals",
        json={"assessment_id": "missing", "approved_by": "tester"},
        headers={"Accept-Language": "en-US,en;q=0.9"},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "assessment not found"


def test_approval_404_detail_localized_zh(client: TestClient) -> None:
    resp = client.post(
        "/approvals",
        json={"assessment_id": "missing", "approved_by": "tester"},
        headers={"Accept-Language": "zh-CN"},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "评估不存在"
