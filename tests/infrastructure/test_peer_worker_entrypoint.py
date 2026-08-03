# tests/infrastructure/test_peer_worker_entrypoint.py
"""Peer-worker entrypoint logic (P2 Task 3).

Loads entrypoint.py via importlib from its file path so we can unit-test the
orchestration logic without building the Docker image. subprocess.run is
monkeypatched to record the command and return a controlled exit code.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

_ENTRYPOINT_PATH = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "secopent"
    / "infrastructure"
    / "peer_agents"
    / "worker_images"
    / "strix"
    / "entrypoint.py"
)


def _load_entrypoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    """Import entrypoint.py as a module with EXCHANGE/OUT redirected to tmp_path."""
    spec = importlib.util.spec_from_file_location("strix_entrypoint", _ENTRYPOINT_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # Redirect the hardcoded paths BEFORE exec_module so main() uses our tmp.
    exchange = tmp_path / "exchange"
    exchange.mkdir(parents=True, exist_ok=True)
    out = exchange / "out"
    out.mkdir(parents=True, exist_ok=True)
    # Patch module-level constants before execution
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    monkeypatch.setattr(mod, "EXCHANGE", exchange)
    monkeypatch.setattr(mod, "OUT", out)
    return mod


class TestEntrypoint:
    def test_builds_correct_strix_command(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mod = _load_entrypoint(tmp_path, monkeypatch)
        exchange = mod.EXCHANGE
        run_id = "run-42"
        targets = ["http://host.docker.internal:3000", "http://api.test:8080"]
        instruction = "Test ONLY these targets."
        (exchange / "input.json").write_text(
            json.dumps(
                {"run_id": run_id, "targets": targets, "instruction": instruction}
            ),
            encoding="utf-8",
        )
        # Fake strix_runs/<run_id>/ with artifacts
        run_dir = exchange / "strix_runs" / run_id
        run_dir.mkdir(parents=True)
        vuln_data = [{"title": "SQLi", "target": "http://x", "severity": "high"}]
        (run_dir / "vulnerabilities.json").write_text(
            json.dumps(vuln_data), encoding="utf-8"
        )
        (run_dir / "run.json").write_text(
            json.dumps({"llm_usage": {"total_cost_usd": 0.5}}), encoding="utf-8"
        )

        captured: list[list[str]] = []

        class FakeProc:
            returncode = 0

        def fake_run(cmd: list[str], **kwargs: Any) -> FakeProc:
            captured.append(cmd)
            return FakeProc()

        monkeypatch.setattr(mod.subprocess, "run", fake_run)

        rc = mod.main()

        assert rc == 0
        assert len(captured) == 1
        cmd = captured[0]
        assert cmd[0] == "strix"
        # Both targets present
        target_indices = [i for i, v in enumerate(cmd) if v == "--target"]
        target_values = [cmd[i + 1] for i in target_indices]
        assert set(target_values) == set(targets)
        assert "--instruction" in cmd
        instr_idx = cmd.index("--instruction")
        assert cmd[instr_idx + 1] == instruction
        assert "--run-name" in cmd
        rn_idx = cmd.index("--run-name")
        assert cmd[rn_idx + 1] == run_id

        # Artifacts lifted to OUT
        out = mod.OUT
        assert (out / "vulnerabilities.json").exists()
        assert (out / "run.json").exists()
        assert json.loads((out / "vulnerabilities.json").read_text(encoding="utf-8")) == vuln_data

    def test_exit_code_passthrough(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mod = _load_entrypoint(tmp_path, monkeypatch)
        exchange = mod.EXCHANGE
        run_id = "run-fail"
        (exchange / "input.json").write_text(
            json.dumps({"run_id": run_id, "targets": ["http://t"]}),
            encoding="utf-8",
        )
        # No strix_runs dir → no artifact lift (but still returns exit code)

        class FakeProc:
            returncode = 3

        monkeypatch.setattr(mod.subprocess, "run", lambda *a, **kw: FakeProc())

        rc = mod.main()
        assert rc == 3
