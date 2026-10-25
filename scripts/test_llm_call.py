"""Quick LLM connectivity test (Phase A Task A1, Step 5 verification).

Key resolution order: ``MINIMAX_API_KEY`` env var, then the key file kept
OUTSIDE the repository at ``F:/claudepc/secrets-local/minimax-key.txt``
(moved out of the repo tree in the 2026-10-25 security review; a credential
file must never live inside the project directory).
DO NOT commit this script's output (contains no key, but verify before sharing).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
KEY_FILE = Path("F:/claudepc/secrets-local/minimax-key.txt")


def load_key() -> str:
    env_key = os.environ.get("MINIMAX_API_KEY", "").strip()
    if env_key:
        return env_key
    if KEY_FILE.is_file():
        return KEY_FILE.read_text(encoding="utf-8").strip()
    print(
        "ERROR: no key - set MINIMAX_API_KEY or place the key file at "
        f"{KEY_FILE}",
        file=sys.stderr,
    )
    return ""


def main() -> int:
    key = load_key()
    if not key:
        return 1
    os.environ["MINIMAX_API_KEY"] = key
    print(f"key loaded: {key[:8]}...{key[-4:]} (len={len(key)})")

    from secopent.infrastructure.llm.config import load_backend_from_config

    backend = load_backend_from_config(REPO / "config" / "llm.yaml")

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
