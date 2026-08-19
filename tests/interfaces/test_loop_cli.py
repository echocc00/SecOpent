"""secopent loop CLI (v0.7.8 M5) - human entry points into the ReasoningLoop.

Small diagnostic commands over a short-lived in-memory loop runtime. The
repos are process-local (shared per-process singleton), so a create -> status
-> history -> stop sequence made from consecutive ``main()`` calls in the same
process observes the same loops. State does NOT persist across separate CLI
process invocations - reported in the command help/docs.
"""
from __future__ import annotations

import re

import pytest

from secopent.interfaces.cli.main import main

_LOOP_ID_RE = re.compile(r"\b[0-9a-f]{8}\b")


def _create_loop(capsys, assessment_id: str = "assess-1") -> str:
    rc = main(["loop", "create", "--assessment-id", assessment_id, "--max-steps", "7"])
    assert rc == 0
    out = capsys.readouterr().out
    _match = _LOOP_ID_RE.search(out)
    assert _match is not None, f"expected a loop_id in output: {out!r}"
    return _match.group(0)


def test_loop_create_prints_loop_id(capsys) -> None:
    loop_id = _create_loop(capsys)
    assert _LOOP_ID_RE.fullmatch(loop_id)


def test_loop_status_reports_phase(capsys) -> None:
    loop_id = _create_loop(capsys)
    rc = main(["loop", "status", "--loop-id", loop_id])
    assert rc == 0
    out = capsys.readouterr().out
    assert "initializing" in out
    assert loop_id in out


def test_loop_history_reports_step_count(capsys) -> None:
    loop_id = _create_loop(capsys)
    rc = main(["loop", "history", "--loop-id", loop_id])
    assert rc == 0
    out = capsys.readouterr().out
    assert "history (0 steps)" in out


def test_loop_stop_transitions_to_stopped_phase(capsys) -> None:
    loop_id = _create_loop(capsys)
    rc = main(["loop", "stop", "--loop-id", loop_id, "--actor", "op"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "emergency_stopped" in out

    # Status now reflects the stopped phase.
    rc = main(["loop", "status", "--loop-id", loop_id])
    assert rc == 0
    out = capsys.readouterr().out
    assert "emergency_stopped" in out


def test_loop_stop_unknown_loop_fails(capsys) -> None:
    rc = main(["loop", "stop", "--loop-id", "deadbeef", "--actor", "op"])
    assert rc == 1
    err = capsys.readouterr()
    assert "error" in (err.out + err.err).lower()


def test_loop_status_unknown_loop_fails(capsys) -> None:
    rc = main(["loop", "status", "--loop-id", "deadbeef"])
    assert rc == 1
    err = capsys.readouterr()
    assert "error" in (err.out + err.err).lower()


def test_loop_create_default_budget_uses_defaults(capsys) -> None:
    """max_steps is optional; defaults come from LoopBudget.default."""
    rc = main(["loop", "create", "--assessment-id", "assess-2"])
    assert rc == 0
    out = capsys.readouterr().out
    _match = _LOOP_ID_RE.search(out)
    assert _match is not None


def test_loop_requires_subcommand() -> None:
    """`secopent loop` with no subcommand is an argparse error (exit 2)."""
    with pytest.raises(SystemExit) as exc:
        main(["loop"])
    assert exc.value.code == 2


def test_loop_create_requires_assessment_id() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["loop", "create"])
    assert exc.value.code == 2


def test_loop_status_requires_loop_id() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["loop", "status"])
    assert exc.value.code == 2
