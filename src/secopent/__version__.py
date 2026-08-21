# src/secopent/__version__.py
"""Single source of truth for the SecOpent version (T9 / §②).

``pyproject.toml`` reads this via ``[tool.setuptools.dynamic] version = {attr =
"secopent.__version__.__version__"}``, and the CLI ``secopent version`` imports
it - so the installed package metadata, the CLI, and the git tag (``v<version>``,
stamped by ``scripts/release.sh``) never drift.
"""
from __future__ import annotations

__version__ = "0.7.1"
