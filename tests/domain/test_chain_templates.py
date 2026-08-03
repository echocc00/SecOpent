# tests/domain/test_chain_templates.py
"""Attack chain templates: curated link patterns (P1a Task 5, consumed by P2b)."""
from __future__ import annotations

import pytest

from secopent.domain.common.errors import DomainValidationError
from secopent.domain.findings.chain_templates import (
    AttackChainTemplate,
    ChainLinkSpec,
    default_chain_templates,
    match_template,
)


class TestTemplateModel:
    def test_template_requires_at_least_two_links(self) -> None:
        with pytest.raises(DomainValidationError):
            AttackChainTemplate(
                id="one-link",
                name="degenerate",
                links=(ChainLinkSpec(cwe_any=("CWE-89",)),),
                tactic="initial-access",
            )

    def test_well_formed_template(self) -> None:
        template = AttackChainTemplate(
            id="ssrf-to-cloud-creds",
            name="SSRF -> cloud metadata -> credential leak",
            links=(
                ChainLinkSpec(cwe_any=("CWE-918",)),
                ChainLinkSpec(
                    cwe_any=("CWE-918",), asset_pattern="169.254.169.254"
                ),
                ChainLinkSpec(cwe_any=("CWE-522", "CWE-312")),
            ),
            tactic="credential-access",
        )
        assert len(template.links) == 3


class TestMatching:
    def test_matches_confirmed_findings_in_order(self) -> None:
        template = AttackChainTemplate(
            id="authz-to-priv",
            name="auth bypass -> IDOR",
            links=(
                ChainLinkSpec(cwe_any=("CWE-287",)),
                ChainLinkSpec(cwe_any=("CWE-639",)),
            ),
            tactic="privilege-escalation",
        )
        # findings as (cwe_tuple, asset) tuples projecting ConfirmedFinding
        findings = (
            (("CWE-287",), "http://app/login"),
            (("CWE-639",), "http://app/api/profile"),
        )
        assert match_template(template, findings) is True

    def test_no_match_when_link_missing(self) -> None:
        template = AttackChainTemplate(
            id="authz-to-priv",
            name="auth bypass -> IDOR",
            links=(
                ChainLinkSpec(cwe_any=("CWE-287",)),
                ChainLinkSpec(cwe_any=("CWE-639",)),
            ),
            tactic="privilege-escalation",
        )
        findings = ((("CWE-287",), "http://app/login"),)
        assert match_template(template, findings) is False


class TestDefaultTemplates:
    def test_first_batch_covers_five_patterns(self) -> None:
        templates = default_chain_templates()
        ids = {t.id for t in templates}
        assert {
            "ssrf-to-cloud-creds",
            "auth-bypass-plus-idor",
            "sqli-to-credential-theft",
            "xss-to-session-theft",
            "weak-creds-to-admin-takeover",
        } <= ids
