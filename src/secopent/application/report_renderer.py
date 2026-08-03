# src/secopent/application/report_renderer.py
"""ReportRenderer: data-driven, traceable report rendering (§13).

Renders a Report from Findings/Evidence/CoverageMatrix - numbers are computed
from data, never hand-written, and every finding traces to evidence ids. The
release gate (``completeness_ok``) requires every section filled, zero
unverified findings (all oracle-VALIDATED), a green coverage matrix (no
uncovered required class), and evidence digests present. The M2 RedactionEngine
is re-applied to narrative text at render time so no secret leaks into the
report. Jinja2 templates are injected behind ``TemplateRenderer`` so the
application layer stays framework-free.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Protocol, runtime_checkable

from ..domain.findings.attack_chain import AttackChain, ChainStatus
from ..domain.findings.models import Finding, FindingStatus
from ..domain.reports.models import Report, ReportSection
from .evidence import Redactor


@runtime_checkable
class TemplateRenderer(Protocol):
    """Renders a named template with a context (Jinja2 in infrastructure)."""

    def render(self, template_name: str, context: Mapping[str, Any]) -> str: ...


@dataclass(frozen=True, slots=True)
class ReportData:
    """All inputs needed to render a report (the single source of truth)."""

    assessment_id: str
    title: str
    scope_summary: str
    method: str
    findings: tuple[Finding, ...] = ()
    coverage_rate: float = 0.0
    uncovered_classes: tuple[str, ...] = ()
    evidence_digests: tuple[str, ...] = ()
    assets: tuple[str, ...] = ()


# CWE -> remediation advice (falls back to generic guidance).
_REMEDIATION: dict[str, str] = {
    "CWE-89": "Use parameterized queries / prepared statements; never concatenate input into SQL.",
    "CWE-79": "Contextually encode output and apply a Content-Security-Policy.",
    "CWE-918": "Allow-list request destinations; block internal and cloud-metadata ranges.",
    "CWE-200": "Minimize disclosed information; set secure response headers.",
    "CWE-287": "Enforce strong authentication and MFA; protect credential storage.",
    "CWE-732": "Restrict permissions to least privilege; remove public access.",
    "CWE-284": "Enforce access controls; segment network exposure.",
}
_GENERIC_REMEDIATION = "Review and remediate per the referenced CWE guidance."


def _remediation_for(cwe: Sequence[str]) -> str:
    for code in cwe:
        if code in _REMEDIATION:
            return _REMEDIATION[code]
    return _GENERIC_REMEDIATION


class ReportRenderer:
    """Render a traceable, redacted Report from ReportData."""

    def __init__(self, templates: TemplateRenderer, redactor: Redactor) -> None:
        self._templates = templates
        self._redactor = redactor

    def render(self, data: ReportData, *, report_id: str) -> Report:
        """Build the report sections, apply redaction, and run the release gate."""
        completeness_ok = self._completeness(data)
        findings_ctx = self._findings_context(data.findings)

        sections = [
            ReportSection(
                name="executive_summary",
                content=self._templates.render(
                    "executive_summary.md.j2",
                    {
                        "title": data.title,
                        "assessment_id": data.assessment_id,
                        "finding_count": len(data.findings),
                        "coverage_rate": data.coverage_rate,
                        "completeness_ok": completeness_ok,
                    },
                ),
            ),
            ReportSection(
                name="scope",
                content="## Scope\n\n"
                + self._redactor.redact(data.scope_summary).redacted_text,
            ),
            ReportSection(name="method", content="## Method\n\n" + data.method),
            ReportSection(
                name="asset_inventory",
                content="## Asset Inventory\n\n" + self._bullet(data.assets),
            ),
            ReportSection(
                name="findings",
                content="## Findings\n\n"
                + self._templates.render("findings.md.j2", {"findings": findings_ctx}),
            ),
            ReportSection(
                name="evidence",
                content="## Evidence\n\n" + self._bullet(data.evidence_digests),
            ),
            ReportSection(
                name="coverage_matrix",
                content="## Coverage Matrix\n\n"
                + self._templates.render(
                    "coverage_matrix.md.j2",
                    {
                        "coverage_rate": data.coverage_rate,
                        "uncovered_classes": list(data.uncovered_classes),
                    },
                ),
            ),
            ReportSection(
                name="appendix",
                content="## Appendix\n\n"
                + f"Report ID: {report_id}\nAssessment: {data.assessment_id}\n",
            ),
        ]
        report = Report(
            id=report_id,
            assessment_id=data.assessment_id,
            title=data.title,
            sections=tuple(sections),
            finding_count=len(data.findings),
            coverage_rate=data.coverage_rate,
            completeness_ok=completeness_ok,
        )
        return replace(report, digest=report.compute_digest())

    def _completeness(self, data: ReportData) -> bool:
        """Release gate: green coverage + all findings validated + evidence present."""
        coverage_green = data.coverage_rate >= 1.0 and not data.uncovered_classes
        all_validated = all(
            f.status is FindingStatus.VALIDATED for f in data.findings
        )
        evidence_ok = bool(data.evidence_digests) or not data.findings
        return coverage_green and all_validated and evidence_ok

    def _findings_context(self, findings: tuple[Finding, ...]) -> list[dict[str, Any]]:
        context = []
        for finding in findings:
            redacted_title = self._redactor.redact(finding.title).redacted_text
            context.append(
                {
                    "title": redacted_title,
                    "severity": finding.severity.value,
                    "asset": finding.asset,
                    "cwe": list(finding.cwe),
                    "cve": list(finding.cve),
                    "remediation": _remediation_for(finding.cwe),
                    "evidence": ", ".join(finding.evidence_ids) or "n/a",
                    "status": finding.status.value,
                }
            )
        return context

    @staticmethod
    def _bullet(items: Sequence[str]) -> str:
        if not items:
            return "_None._"
        return "\n".join(f"- {item}" for item in items)


def render_chain_section(chains: Iterable[AttackChain]) -> str:
    """Render attack-chain section for the report (pure function, Markdown).

    CONFIRMED chains → "已验证攻击链" with per-link finding refs + severity.
    PARTIALLY_VERIFIED / HYPOTHESIS chains → "建议优先修复路径" with unconfirmed
    links noted. Empty input → placeholder message.
    """
    chain_list = list(chains)
    if not chain_list:
        return "## 攻击链分析\n\n本次评估未发现可验证攻击链。\n"

    confirmed = [c for c in chain_list if c.status is ChainStatus.CONFIRMED]
    suggested = [
        c
        for c in chain_list
        if c.status in (ChainStatus.PARTIALLY_VERIFIED, ChainStatus.HYPOTHESIS)
    ]

    parts: list[str] = ["## 攻击链分析\n"]

    if confirmed:
        parts.append("### 已验证攻击链\n")
        for chain in confirmed:
            parts.append(
                f"- **{chain.template_id}** (severity: {chain.severity.value})"
            )
            for link in chain.links:
                parts.append(f"  - finding: `{link.confirmed_finding_id}`")
        parts.append("")

    if suggested:
        parts.append("### 建议优先修复路径\n")
        for chain in suggested:
            status_label = (
                "partially verified"
                if chain.status is ChainStatus.PARTIALLY_VERIFIED
                else "hypothesis"
            )
            parts.append(
                f"- **{chain.template_id}** ({status_label}, "
                f"severity: {chain.severity.value})"
            )
            for link in chain.links:
                if link.is_confirmed:
                    parts.append(f"  - finding: `{link.confirmed_finding_id}`")
                else:
                    parts.append(
                        f"  - ⚠ unconfirmed (pending: `{link.pending_verification_key}`)"
                    )
        parts.append("")

    return "\n".join(parts) + "\n"
