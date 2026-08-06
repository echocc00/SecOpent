# src/secopent/infrastructure/llm/config.py
"""Build an LLM backend from config/llm.yaml (§12.11, v0.5.0 Phase 3).

Reads the YAML config (``backend:`` = remote | ollama | null, plus
endpoint / api_key_env / model) and returns the matching backend:
- ``remote``: any OpenAI-compatible API (MiniMax/DeepSeek/Qwen/OpenAI/Claude);
  requires the ``api_key_env`` environment variable to be set;
- ``ollama``: a locally running ``ollama serve`` (no API key, no cloud egress);
- ``null``: the offline no-op backend.

Raises ``LLMError`` on a malformed/unusable config; callers degrade gracefully.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from ...application.remote_model import ModelBackend
from . import LLMError
from .null_backend import NullModelBackend
from .ollama_backend import DEFAULT_ENDPOINT, DEFAULT_MODEL, OllamaBackend
from .remote_openai_backend import RemoteOpenAICompatibleBackend


def load_backend_from_config(path: Path) -> ModelBackend:
    """Load config/llm.yaml and build the configured backend."""
    data: dict[str, Any] = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    backend = str(data.get("backend", "remote"))
    if backend == "ollama":
        endpoint = str(data.get("endpoint", "") or "") or DEFAULT_ENDPOINT
        model = str(data.get("model", "") or "") or DEFAULT_MODEL
        return OllamaBackend(endpoint=endpoint, model=model)
    if backend == "null":
        return NullModelBackend()
    if backend != "remote":
        raise LLMError(
            f"unsupported LLM backend {backend!r} (expected remote, ollama or null)"
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
