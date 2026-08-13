"""Self-tests for scripts/lint_forbidden_patterns.py (v0.3.0 T1).

The linter encodes the v3/v4/v5 invariants (no raw router threads, no
hot-path open_session, audit .record must thread session=). These tests pin
the rules with synthetic violations in a tmp tree plus a whole-tree check
that the real source is clean.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "lint_forbidden_patterns.py"


def _run(root: Path | None = None) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(_SCRIPT)]
    if root is not None:
        cmd += ["--root", str(root)]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)  # noqa: S603


def test_real_tree_is_clean() -> None:
    result = _run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "clean" in result.stdout


def test_r1_flags_thread_in_router(tmp_path: Path) -> None:
    router = tmp_path / "interfaces" / "api" / "routers"
    router.mkdir(parents=True)
    (router / "bad.py").write_text(
        "import threading\nthreading.Thread(target=lambda: None).start()\n",
        encoding="utf-8",
    )
    result = _run(tmp_path)
    assert result.returncode == 1
    assert "R1" in result.stdout
    assert "bad.py:2" in result.stdout


def test_r1_ignores_comment_mentions(tmp_path: Path) -> None:
    router = tmp_path / "interfaces" / "api" / "routers"
    router.mkdir(parents=True)
    (router / "ok.py").write_text(
        "# previously used threading.Thread(...); now BackgroundTasks\n",
        encoding="utf-8",
    )
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout


def test_r2_flags_open_session_outside_allowlist(tmp_path: Path) -> None:
    mod = tmp_path / "infrastructure"
    mod.mkdir()
    (mod / "bad.py").write_text("s = db.open_session()\n", encoding="utf-8")
    result = _run(tmp_path)
    assert result.returncode == 1
    assert "R2" in result.stdout


def test_r2_allows_sanctioned_module(tmp_path: Path) -> None:
    mod = tmp_path / "infrastructure" / "audit"
    mod.mkdir(parents=True)
    (mod / "database_recorder.py").write_text(
        "s = self._db.open_session()\n", encoding="utf-8"
    )
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout


def test_r3_flags_record_without_session(tmp_path: Path) -> None:
    app = tmp_path / "application"
    app.mkdir()
    (app / "canary.py").write_text(
        "def f(self) -> None:\n    self._audit.record(actor='x', action='y')\n",
        encoding="utf-8",
    )
    result = _run(tmp_path)
    assert result.returncode == 1
    assert "R3" in result.stdout


def test_r3_passes_when_session_threaded(tmp_path: Path) -> None:
    app = tmp_path / "application"
    app.mkdir()
    (app / "canary.py").write_text(
        "def f(self) -> None:\n"
        "    self._audit.record(actor='x', action='y', session=None)\n",
        encoding="utf-8",
    )
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout


def test_r3b_flags_audit_chain_record_without_session(tmp_path: Path) -> None:
    app = tmp_path / "application"
    app.mkdir()
    (app / "execution.py").write_text(
        "def f(audit_chain) -> None:\n    audit_chain.record(actor='x')\n",
        encoding="utf-8",
    )
    result = _run(tmp_path)
    assert result.returncode == 1
    assert "R3b" in result.stdout


def test_r4_flags_duplicate_scope_matcher(tmp_path: Path) -> None:
    """A second host-vs-rule matcher outside domain/scope/models.py must fail.

    v9 class: ScopeEnforcer's private _host_matches_rule drifted from
    _target_matches and rejected every HTTP-prefixed scope rule until v0.6.1.
    """
    app = tmp_path / "application"
    app.mkdir()
    (app / "scope_enforcer.py").write_text(
        "def _host_matches_rule(host: str, rule: str) -> bool:\n"
        "    return host == rule\n",
        encoding="utf-8",
    )
    result = _run(tmp_path)
    assert result.returncode == 1
    assert "R4" in result.stdout


def test_r4_allows_the_single_source_of_truth(tmp_path: Path) -> None:
    domain = tmp_path / "domain" / "scope"
    domain.mkdir(parents=True)
    (domain / "models.py").write_text(
        "def _target_matches(self, rule: str, value: str) -> bool:\n"
        "    return True\n",
        encoding="utf-8",
    )
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout


def test_r3b_ignores_audit_service_record_in_execution(tmp_path: Path) -> None:
    """execution.py's AuditService(...).record is session-bound via its repo."""
    app = tmp_path / "application"
    app.mkdir()
    (app / "execution.py").write_text(
        "def f(audit_repo) -> None:\n"
        "    AuditService(audit_repo).record(actor='x')\n",
        encoding="utf-8",
    )
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout


def test_missing_root_is_an_error(tmp_path: Path) -> None:
    result = _run(tmp_path / "does-not-exist")
    assert result.returncode == 2
