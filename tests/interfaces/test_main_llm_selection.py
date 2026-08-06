"""LLM backend selection: config-driven + env override (v0.5.0 Phase 3, 3.4+3.5).

Precedence under test (errata E4): SECOPTENT_LLM_BACKEND env override >
config file ``backend:`` field > legacy MINIMAX_API_KEY fallback > null.
Misconfiguration degrades to the null backend - never a broken boot.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from secopent.infrastructure.llm.null_backend import NullModelBackend
from secopent.infrastructure.llm.ollama_backend import OllamaBackend
from secopent.infrastructure.llm.remote_openai_backend import RemoteOpenAICompatibleBackend
from secopent.interfaces.api.main import _build_llm_backend


@pytest.fixture(autouse=True)
def _clean_llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("SECOPTENT_LLM_BACKEND", "SECOPTENT_LLM_CONFIG", "MINIMAX_API_KEY"):
        monkeypatch.delenv(var, raising=False)


def _write_config(tmp_path: Path, text: str) -> Path:
    config = tmp_path / "llm.yaml"
    config.write_text(text, encoding="utf-8")
    return config


def test_config_ollama_backend(tmp_path: Path) -> None:
    config = _write_config(
        tmp_path,
        "backend: ollama\nendpoint: http://ollama.local:11434\nmodel: qwen2.5:7b\n",
    )
    backend = _build_llm_backend(config_path=config)
    assert isinstance(backend, OllamaBackend)
    assert backend._endpoint == "http://ollama.local:11434"
    assert backend._model == "qwen2.5:7b"


def test_config_ollama_defaults_when_fields_missing(tmp_path: Path) -> None:
    config = _write_config(tmp_path, "backend: ollama\n")
    backend = _build_llm_backend(config_path=config)
    assert isinstance(backend, OllamaBackend)
    assert backend._endpoint == "http://localhost:11434"
    assert backend._model == "llama3.1:8b"


def test_config_remote_backend_with_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_LLM_KEY", "sk-test")
    config = _write_config(
        tmp_path,
        "backend: remote\nendpoint: https://api.deepseek.com/v1\n"
        "api_key_env: TEST_LLM_KEY\nmodel: deepseek-chat\n",
    )
    backend = _build_llm_backend(config_path=config)
    assert isinstance(backend, RemoteOpenAICompatibleBackend)


def test_config_remote_missing_key_degrades_to_null(tmp_path: Path) -> None:
    config = _write_config(
        tmp_path,
        "backend: remote\nendpoint: https://api.deepseek.com/v1\n"
        "api_key_env: UNSET_KEY_XYZ\nmodel: deepseek-chat\n",
    )
    assert isinstance(_build_llm_backend(config_path=config), NullModelBackend)


def test_config_null_backend(tmp_path: Path) -> None:
    config = _write_config(tmp_path, "backend: null\n")
    assert isinstance(_build_llm_backend(config_path=config), NullModelBackend)


def test_config_unsupported_backend_degrades_to_null(tmp_path: Path) -> None:
    config = _write_config(tmp_path, "backend: carrier-pigeon\n")
    assert isinstance(_build_llm_backend(config_path=config), NullModelBackend)


def test_env_override_ollama_wins_over_remote_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECOPTENT_LLM_BACKEND", "ollama")
    config = _write_config(
        tmp_path,
        "backend: remote\nendpoint: https://api.minimax.chat/v1\n"
        "api_key_env: MINIMAX_API_KEY\nmodel: abab6.5s-chat\n",
    )
    backend = _build_llm_backend(config_path=config)
    assert isinstance(backend, OllamaBackend)
    # The config describes a remote backend, so ollama uses its defaults.
    assert backend._endpoint == "http://localhost:11434"


def test_env_override_null_wins_over_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECOPTENT_LLM_BACKEND", "null")
    config = _write_config(tmp_path, "backend: ollama\n")
    assert isinstance(_build_llm_backend(config_path=config), NullModelBackend)


def test_no_config_minimax_key_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Backward compat: pre-v0.5.0 deployments rely on MINIMAX_API_KEY alone."""
    monkeypatch.setenv("MINIMAX_API_KEY", "sk-minimax")
    backend = _build_llm_backend(config_path=tmp_path / "absent.yaml")
    assert isinstance(backend, RemoteOpenAICompatibleBackend)
    assert backend._endpoint == "https://api.minimax.chat/v1"


def test_no_config_no_key_is_null(tmp_path: Path) -> None:
    backend = _build_llm_backend(config_path=tmp_path / "absent.yaml")
    assert isinstance(backend, NullModelBackend)


def test_create_app_wires_selected_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Smoke: the composition root uses _build_llm_backend end-to-end."""
    from secopent.infrastructure.db.sqlite import create_sqlite_engine
    from secopent.interfaces.api.main import create_app

    config = _write_config(tmp_path, "backend: null\n")
    monkeypatch.setenv("SECOPTENT_LLM_CONFIG", str(config))
    app = create_app(engine=create_sqlite_engine(tmp_path / "llm.db"))
    assert isinstance(app.state.model_gateway._local, NullModelBackend)
