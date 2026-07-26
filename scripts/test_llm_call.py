"""Quick LLM connectivity test (Phase A Task A1, Step 5 verification).

Reads MiniMax key from minimax-key.txt, sets env, calls RemoteOpenAICompatibleBackend.
DO NOT commit this script's output (contains no key, but verify before sharing).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def load_key() -> str:
    key_file = REPO / "minimax-key.txt"
    if not key_file.is_file():
        print("ERROR: minimax-key.txt not found", file=sys.stderr)
        return ""
    return key_file.read_text(encoding="utf-8").strip()


def main() -> int:
    key = load_key()
    if not key:
        return 1
    os.environ["MINIMAX_API_KEY"] = key
    print(f"key loaded: {key[:8]}...{key[-4:]} (len={len(key)})")

    from secopent.infrastructure.llm.remote_openai_backend import RemoteOpenAICompatibleBackend

    backend = RemoteOpenAICompatibleBackend(
        endpoint="https://api.minimax.chat/v1",
        api_key_env="MINIMAX_API_KEY",
        model="abab6.5s-chat",
        timeout=30.0,
    )

    print("\n=== is_available ===")
    print(f"available: {backend.is_available()}")

    print("\n=== generate (simple prompt) ===")
    try:
        resp = backend.generate(
            messages=[
                {"role": "system", "content": "You are a concise assistant. Reply in one short sentence."},
                {"role": "user", "content": "Say hello and confirm you are working."},
            ],
            max_tokens=64,
            temperature=0.2,
        )
        print(f"model: {resp.model}")
        print(f"tokens: prompt={resp.prompt_tokens} completion={resp.completion_tokens}")
        print(f"finish_reason: {resp.finish_reason}")
        print(f"text: {resp.text!r}")
        return 0
    except Exception as exc:
        print(f"FAILED: {type(exc).__name__}: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
