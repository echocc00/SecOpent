"""TDD tests for the CLI (M4 Task 6, §13 - runs from any CWD)."""
from __future__ import annotations

from secopent.interfaces.cli.main import __version__, main


def test_version_prints_and_succeeds(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["version"]) == 0
    assert __version__ in capsys.readouterr().out


def test_doctor_healthy(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["doctor"]) == 0
    assert "ok" in capsys.readouterr().out


def test_no_command_shows_help_and_fails(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main([]) == 1
    assert "usage" in capsys.readouterr().out.lower()


def test_runs_from_any_cwd(tmp_path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    # The CLI resolves nothing relative to CWD, so it works from anywhere.
    monkeypatch.chdir(tmp_path)
    assert main(["doctor"]) == 0
    assert "ok" in capsys.readouterr().out


def test_upgrade_dry_run_lists_steps(capsys) -> None:  # type: ignore[no-untyped-def]
    """--dry-run prints the upgrade steps without executing them."""
    assert main(["upgrade", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "git pull" in out
    assert "alembic upgrade head" in out
    assert "restart" in out.lower()


def test_upgrade_no_frontend_no_migrate_dry_run(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["upgrade", "--dry-run", "--no-frontend", "--no-migrate"]) == 0
    out = capsys.readouterr().out
    assert "frontend: skipped" in out
    assert "migration: skipped" in out
