"""CanaryTokenManager accepts any AuditRecorder (W3-A T1).

The shared signed AuditChain must satisfy canary's audit sink so canary events
land in the tamper-evident chain, not just the DB audit log. This requires
AuditRecorder to live in ports/ and canary's audit type to be widened off the
session-bound AuditService.
"""
from __future__ import annotations

from secopent.application.audit_chain import AuditChain
from secopent.application.canary import CanaryTokenManager
from secopent.application.ports.audit import AuditRecorder
from secopent.infrastructure.audit.key_manager import AuditKeyManager


def test_canary_accepts_shared_audit_chain() -> None:
    chain = AuditChain(AuditKeyManager())
    canary = CanaryTokenManager(chain)
    token = canary.generate(actor="oracle", candidate_id="cand-1")
    assert token
    # The canary.generated event is signed into the tamper-evident chain.
    assert chain.verify() is True
    assert any(e.action == "canary.generated" for e in chain.events())
    # AuditChain satisfies AuditRecorder structurally (runtime_checkable).
    assert isinstance(chain, AuditRecorder)


def test_canary_verify_echo_audited_to_chain() -> None:
    chain = AuditChain(AuditKeyManager())
    canary = CanaryTokenManager(chain)
    token = canary.generate(actor="oracle", candidate_id="cand-2")
    canary.verify_echo(f"prefix-{token}-suffix", token, actor="oracle")
    actions = [e.action for e in chain.events()]
    assert "canary.generated" in actions
    assert "canary.verified" in actions
    assert chain.verify() is True
