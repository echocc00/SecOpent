# src/secopent/infrastructure/llm/config.py
"""Build an LLM backend from config/llm.yaml (§12.11).

Reads the YAML config (backend / endpoint / api_key_env / model), validates the
API key env var is set, and returns the matching backend. Currently the
``remote`` backend (OpenAI-compatible: MiniMax/DeepSeek/Qwen/OpenAI/Claude); a
local Ollama backend is reserved for a later phase.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from . import LLMError
from .remote_openai_backend import RemoteOpenAICompatibleBackend


def load_backend_from_config(path: Path) -> RemoteOpenAICompatibleBackend:
    """Load config/llm.yaml and build the configured remote backend."""
    data: dict[str, Any] = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    backend = str(data.get("backend", "remote"))
    if backend != "remote":
        raise LLMError(
            f"unsupported LLM backend {backend!r} (only 'remote' is implemented; "
            "local Ollama is reserved for a later phase)"
        )
    api_key_env = str(data.get("api_key_env", ""))
    if not api_key_env or not os.environ.get(api_key_env):
        raise LLMError(
            f"LLM API key not set: environment variable {api_key_env!r} is empty"
        )
    endpoint = str(data.get("endpoint", ""))
    model = str(data.get("model", ""))
    if not endpoint or not model:
        raise LLMError("LLM config requires 'endpoint' and 'model'")
    return RemoteOpenAICompatibleBackend(
        endpoint=endpoint,
        api_key_env=api_key_env,
        model=model,
    )
