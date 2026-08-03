# tests/application/test_deliverables.py
"""Deliverables directory contract (P1b Task 5)."""
from __future__ import annotations

from pathlib import Path

import pytest

from secopent.application.deliverables import (
    DeliverablesLayout,
    DeliverableValidationError,
    read_deliverable,
    validate_layout,
    write_deliverable,
)


class TestLayout:
    def test_phase_paths_are_deterministic(self, tmp_path: Path) -> None:
        layout = DeliverablesLayout(root=tmp_path)
        expected = tmp_path / "deliverables" / "recon_deliverable.md"
        assert layout.deliverable_path("recon") == expected
        assert layout.scratchpad_dir() == tmp_path / "scratchpad"

    def test_write_then_read_roundtrip(self, tmp_path: Path) -> None:
        layout = DeliverablesLayout(root=tmp_path)
        write_deliverable(layout, "recon", "# Recon\n- endpoint /api\n")
        assert read_deliverable(layout, "recon").startswith("# Recon")

    def test_validate_rejects_missing_required_phase(self, tmp_path: Path) -> None:
        layout = DeliverablesLayout(root=tmp_path)
        write_deliverable(layout, "recon", "x")
        with pytest.raises(DeliverableValidationError):
            validate_layout(layout, required_phases=("recon", "report"))

    def test_validate_rejects_empty_deliverable(self, tmp_path: Path) -> None:
        layout = DeliverablesLayout(root=tmp_path)
        write_deliverable(layout, "recon", "   \n")
        with pytest.raises(DeliverableValidationError):
            validate_layout(layout, required_phases=("recon",))

    def test_validate_accepts_complete_layout(self, tmp_path: Path) -> None:
        layout = DeliverablesLayout(root=tmp_path)
        write_deliverable(layout, "recon", "content")
        write_deliverable(layout, "report", "content")
        validate_layout(layout, required_phases=("recon", "report"))  # no raise
