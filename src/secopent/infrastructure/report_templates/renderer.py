# src/secopent/infrastructure/report_templates/renderer.py
"""Jinja2 template renderer for reports (§13 data-driven rendering).

Loads ``.j2`` templates from this directory and renders them with a strict
context (an undefined variable is an error, so a report can never silently drop
a field). The ReportRenderer (application) injects this behind its
``TemplateRenderer`` protocol so the application layer stays free of Jinja2.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape


class Jinja2TemplateRenderer:
    """Render named ``.j2`` templates from the report_templates directory."""

    def __init__(self, template_dir: Path | None = None) -> None:
        self._dir = Path(template_dir) if template_dir is not None else Path(__file__).parent
        self._env = Environment(
            loader=FileSystemLoader(str(self._dir)),
            # Reports are Markdown (.md.j2), not HTML: select_autoescape scopes
            # autoescaping to HTML/XML templates and correctly leaves these
            # Markdown templates unescaped (HTML-escaping would corrupt the
            # Markdown source). Satisfies bandit B701; any later Markdown->HTML
            # rendering step owns its own sanitization.
            autoescape=select_autoescape(),
            undefined=StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def render(self, template_name: str, context: Mapping[str, Any]) -> str:
        return self._env.get_template(template_name).render(**context)
