# src/secopent/infrastructure/reasoning_loop/composition.py
"""Composition wiring for the ReasoningLoop proposer (v0.7.1 Task 4).

``create_loop_proposer`` selects the proposer from ``SECOPENT_LOOP_PROPOSER``:

- ``mock`` (default): a ``MockLoopActionProposer`` (empty script -> propose
  returns ``None``, so the orchestrator records a transient backend-unavailable
  step). No audit is emitted for an explicit mock choice.
- ``real``: wires a ``RealLoopActionProposer`` over the configured LLM backend.
  If the backend is unavailable or could not be built (no API key / bad/broken
  config), the factory degrades to the Mock proposer and records a
  ``loop.fallback_used`` audit event — the SchemaGate is NEVER weakened.

The ``_RealProposerPort`` adapter maps the rich ``LLMProposalResult`` (the real
proposer's own return type) onto the orchestrator's ``LoopActionProposer`` port
(``ProposeAction | None``): ``OK`` yields the action, any other outcome yields
``None`` so the loop records a transient no-op step and applies its own
degradation policy.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ...application.ports.audit import AuditRecorder
from ...application.ports.loop_proposer import LoopActionProposer
from ...application.reasoning_loop.audit import LOOP_FALLBACK_USED
from ...application.reasoning_loop.llm_backend import (
    LoopLLMBackend,
    ProposalOutcome,
)
from ...application.reasoning_loop.mock_proposer import MockLoopActionProposer
from ...application.reasoning_loop.proposer import RealLoopActionProposer
from ...domain.reasoning_loop.models import LoopContext, ProposeAction
from ..llm.config import load_backend_from_config
from ..llm.null_backend import NullModelBackend

LOOP_PROPOSER_ENV = "SECOPENT_LOOP_PROPOSER"
DEFAULT_PROPOSER_MODE = "mock"
LOOP_RESOURCE_TYPE = "reasoning_loop"

# Env vars reuse the existing LLM config-wiring (SECOPTENT_LLM_CONFIG) with a
# repo-relative default, mirroring interfaces/api/main.py.
_LLM_CONFIG_ENV = "SECOPTENT_LLM_CONFIG"
_LLM_CONFIG_DEFAULT = "config/llm.yaml"


class _RealProposerPort(LoopActionProposer):
    """Maps ``RealLoopActionProposer``'s LLMProposalResult onto the port.

    Non-``OK`` outcomes return ``None`` so the orchestrator records a transient
    backend-unavailable step instead of ever fabricating an action from junk.
    """

    def __init__(self, inner: RealLoopActionProposer) -> None:
        self._inner = inner

    def propose(self, context: LoopContext) -> ProposeAction | None:
        result = self._inner.propose(context)
        if (
            result.outcome is ProposalOutcome.OK
            and isinstance(result.action, ProposeAction)
        ):
            return result.action
        return None


def _mock_proposer() -> LoopActionProposer:
    """An empty-script Mock proposer: propose always returns None."""
    return MockLoopActionProposer(script=[])


def _configured_backend(config_path: Path) -> LoopLLMBackend | None:
    """Build the LLM backend from config; None if it is unusable/absent.

    A ``NullModelBackend`` (empty completion, offline fallback) or a config
    failure (no API key, missing file) means there is no REAL LLM to drive the
    loop proposer, so the caller degrades to Mock.
    """
    if not config_path.is_file():
        return None
    try:
        backend = load_backend_from_config(config_path)
    except Exception:
        return None
    if isinstance(backend, NullModelBackend):
        return None
    # ``load_backend_from_config`` returns a ModelBackend (Ollama /
    # RemoteOpenAICompatible), which structurally satisfies LoopLLMBackend
    # (complete(prompt) -> str).
    return backend


def _backend_usable(backend: LoopLLMBackend | None) -> bool:
    """True when a real LLM backend is available to call.

    An injected backend without a probe (``is_available``) is assumed usable;
    a backend that reports unavailable (or is a null/empty backend) is not.
    """
    if backend is None:
        return False
    if isinstance(backend, NullModelBackend):
        return False
    probe = getattr(backend, "is_available", None)
    if callable(probe):
        try:
            return bool(probe())
        except Exception:
            return False
    return True


def _build_real_backend(
    backend: LoopLLMBackend | None,
    *,
    env: Mapping[str, str],
    config_path: Path | None,
) -> LoopLLMBackend | None:
    """Resolve the real backend: injected one wins over the configured one."""
    if backend is not None:
        return backend
    path = config_path or Path(env.get(_LLM_CONFIG_ENV, _LLM_CONFIG_DEFAULT))
    return _configured_backend(path)


def create_loop_proposer(
    *,
    audit: AuditRecorder,
    env: Mapping[str, str],
    backend: LoopLLMBackend | None = None,
    config_path: Path | None = None,
) -> LoopActionProposer:
    """Return the configured LoopActionProposer, degrading to Mock when safe.

    ``backend`` is injected (tests / composition root); when absent, the
    factory builds a real backend from LLM config (``SECOPTENT_LLM_CONFIG`` or
    ``config/llm.yaml``). ``config_path`` pins the config location for tests.
    """
    mode = str(env.get(LOOP_PROPOSER_ENV, DEFAULT_PROPOSER_MODE)).strip().lower()
    if mode != "real":
        return _mock_proposer()

    real_backend = _build_real_backend(backend, env=env, config_path=config_path)
    if not _backend_usable(real_backend):
        reason = (
            "configured LLM backend unavailable"
            if real_backend is not None
            else "no LLM backend configured"
        )
        audit.record(
            actor="reasoning_loop",
            action=LOOP_FALLBACK_USED,
            resource_type=LOOP_RESOURCE_TYPE,
            resource_id="proposer",
            payload={"requested_mode": mode, "reason": reason},
        )
        return _mock_proposer()

    # ``_backend_usable`` is True only when the backend is non-None and usable
    # (injected or built from config). Narrow for the port construction below.
    assert real_backend is not None
    return _RealProposerPort(
        RealLoopActionProposer(backend=real_backend, max_retries=1)
    )