"""Remote OpenAI-compatible LLM backend (Phase A Task A1, Step 5).

Works with any OpenAI-compatible /v1/chat/completions API:
- MiniMax (https://api.minimax.chat/v1)
- DeepSeek (https://api.deepseek.com/v1)
- Qwen/通义 (https://dashscope.aliyuncs.com/compatible-mode/v1)
- OpenAI (https://api.openai.com/v1)
- Claude (via OpenAI-compatible proxy)

Config (config/llm.yaml):
    backend: remote
    endpoint: https://api.minimax.chat/v1
    api_key_env: MINIMAX_API_KEY   # read API key from env var
    model: abab6.5s-chat            # MiniMax model (or deepseek-chat, gpt-4o-mini, etc.)
    max_tokens: 2048
    temperature: 0.2

The backend is injected into RemoteModelGateway (application/remote_model.py),
which enforces data classification + redaction + budget/rate limits BEFORE
calling generate(). This backend just does the HTTP call.
"""
from __future__ import annotations

import os

import httpx

from . import LLMError, LLMResponse


class RemoteOpenAICompatibleBackend:
    """OpenAI-compatible remote LLM backend (MiniMax/DeepSeek/Qwen/OpenAI/Claude)."""

    def __init__(
        self,
        *,
        endpoint: str,
        api_key_env: str,
        model: str,
        timeout: float = 60.0,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._api_key_env = api_key_env
        self._model = model
        self._timeout = timeout

    def _api_key(self) -> str:
        key = os.environ.get(self._api_key_env, "")
        if not key:
            raise LLMError(f"API key env var {self._api_key_env} not set")
        return key

    def is_available(self) -> bool:
        """Check API key configured + endpoint reachable with a minimal HEAD/GET."""
        if not os.environ.get(self._api_key_env):
            return False
        try:
            with httpx.Client(timeout=5.0) as client:
                # Minimal models list call (OpenAI-compatible); 200/401/403 all mean reachable
                resp = client.get(
                    f"{self._endpoint}/models",
                    headers={"Authorization": f"Bearer {self._api_key()}"},
                )
                return resp.status_code in (200, 401, 403)
        except httpx.HTTPError:
            return False

    def generate(
        self,
        *,
        messages: list[dict[str, str]],
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> LLMResponse:
        """Call /v1/chat/completions. Raises LLMError on any failure."""
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.post(
                    f"{self._endpoint}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self._api_key()}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self._model,
                        "messages": messages,
                        "max_tokens": max_tokens,
                        "temperature": temperature,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            raise LLMError(f"LLM API status {exc.response.status_code}: {exc}") from exc
        except httpx.HTTPError as exc:
            raise LLMError(f"LLM API network error: {exc}") from exc
        except (KeyError, ValueError) as exc:
            raise LLMError(f"LLM API malformed response: {exc}") from exc

        choice = data.get("choices", [{}])[0]
        return LLMResponse(
            text=choice.get("message", {}).get("content", ""),
            model=data.get("model", self._model),
            prompt_tokens=data.get("usage", {}).get("prompt_tokens", 0),
            completion_tokens=data.get("usage", {}).get("completion_tokens", 0),
            finish_reason=choice.get("finish_reason", "stop"),
        )
