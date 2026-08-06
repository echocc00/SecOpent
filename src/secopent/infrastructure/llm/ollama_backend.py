# src/secopent/infrastructure/llm/ollama_backend.py
"""Local Ollama LLM backend (v0.5.0 Phase 3, 3.4).

Talks to a locally running ``ollama serve`` (default http://localhost:11434).
No API key and no cloud egress - suited to air-gapped or cost-sensitive
deployments. Implements both integration points:
- the application-layer ``ModelBackend`` Protocol (``complete``) - what
  RemoteModelGateway injects; classification/redaction still runs BEFORE the
  call, so local models get the same governance as remote ones;
- the infrastructure ``LLMBackend`` Protocol (``generate`` / ``is_available``).

The operator owns the Ollama install (``ollama serve`` + ``ollama pull
<model>``); see docs/deployment for setup notes.
"""
from __future__ import annotations

import httpx

from . import LLMError, LLMResponse

DEFAULT_ENDPOINT = "http://localhost:11434"
DEFAULT_MODEL = "llama3.1:8b"


class OllamaBackend:
    """Local Ollama backend over ``/api/generate`` (non-streaming)."""

    def __init__(
        self,
        *,
        endpoint: str = DEFAULT_ENDPOINT,
        model: str = DEFAULT_MODEL,
        timeout: float = 120.0,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._model = model
        self._timeout = timeout
        # Mirrors RemoteOpenAICompatibleBackend: lets callers verify the
        # gateway redacted SENSITIVE data before it reached the model.
        self.last_sent_prompt: str | None = None

    def complete(self, prompt: str) -> str:
        """Satisfy the application-layer ModelBackend Protocol."""
        self.last_sent_prompt = prompt
        return self.generate(prompt=prompt).text

    def is_available(self) -> bool:
        """True when the Ollama server answers /api/tags."""
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"{self._endpoint}/api/tags")
                return resp.status_code == 200
        except httpx.HTTPError:
            return False

    def generate(
        self,
        *,
        messages: list[dict[str, str]] | None = None,
        prompt: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> LLMResponse:
        """Call ``/api/generate`` with ``stream=false``. Raises LLMError.

        Accepts either a raw ``prompt`` or OpenAI-style ``messages`` (flattened
        into one prompt, since Ollama's generate API is prompt-based).
        """
        if prompt is None:
            prompt = "\n".join(
                f"{m.get('role', 'user')}: {m.get('content', '')}"
                for m in (messages or [])
            )
        self.last_sent_prompt = prompt
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.post(
                    f"{self._endpoint}/api/generate",
                    json={
                        "model": self._model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "num_predict": max_tokens,
                            "temperature": temperature,
                        },
                    },
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            raise LLMError(f"Ollama status {exc.response.status_code}: {exc}") from exc
        except httpx.HTTPError as exc:
            raise LLMError(f"Ollama network error: {exc}") from exc
        except (KeyError, ValueError) as exc:
            raise LLMError(f"Ollama malformed response: {exc}") from exc
        return LLMResponse(
            text=str(data.get("response", "")),
            model=str(data.get("model", self._model)),
            prompt_tokens=int(data.get("prompt_eval_count", 0)),
            completion_tokens=int(data.get("eval_count", 0)),
            finish_reason="stop",
        )
