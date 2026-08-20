"""SecOpent ReasoningLoop A/B batch runner (v0.7.9 Task 4).

Operator/human tool, NOT a CI gate. Drives the control arm (deterministic
catalog floor) and the experiment arm (catalog + ReasoningLoop with a real or
mock proposer) across the three provisioned A/B targets (Juice Shop / cr_api /
vulhub), aggregates the per-target metrics into ``test-results/reasoning_loop_ab.json``
(same schema as ``tests/e2e_real/test_reasoning_loop_ab.py``) and prints a
decision-criteria table with a pass/freeze verdict.

Run:  py -3.12 scripts/ab_reasoning_loop.py [--targets ...] [--proposer real|mock] [--dry-run]

The A/B criteria (authoritative spec section 10):
  RELEASE  <=  oracle_confirmed_delta > 0  AND  cost_ratio < 1.5x
  FREEZE   <=  otherwise (keep the catalog floor; mark loop experimental)

Notes:
- Cost model (resolved): the deterministic catalog-floor control consumes
  ~zero LLM tokens, so ``cost_tokens`` is only meaningful for the experiment
  arm. The script therefore expresses comparable single-run "cost" as
  ``wall_seconds`` for BOTH arms and computes ``cost_ratio =
  experiment_wall / control_wall`` against the 1.5x threshold, in addition to
  reporting the experiment's audited token spend. Verdict uses the wall-based
  ratio. No result numbers are fabricated.
- False-positive rate = oracle REFUTED / candidates (advisory; if the
  experiment FP-rate exceeds the control by >1.5x it is noted but does not
  change the CI verdict).
- This script does NOT import pytest fixtures. It reuses the standalone A/B
  drive helpers (``_run_catalog_floor`` / ``_run_reasoning_loop`` /
  ``_write_ab_report``) from the test module, which take explicit URL/mount
  args and are importable outside a pytest session.
"""
from __future__ import annotations

import argparse
import datetime
import shutil
import sys
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_RESULTS = REPO_ROOT / "test-results"
DEFAULT_OUT = TEST_RESULTS / "reasoning_loop_ab.json"

TARGETS_DEFAULT = ("juice_shop", "cr_api", "vulhub")
TARGET_URLS = {
    "juice_shop": "http://localhost:3000",
    "cr_api": "http://localhost:8000",
    "vulhub": "http://localhost:8081",
}

# Acceptance thresholds (spec section 10).
COST_RATIO_THRESHOLD = 1.5
FP_RATIO_THRESHOLD = 1.5


def _ensure_ab_helpers():
    """Import the standalone A/B drive helpers from the e2e_real test module.

    The test module imports ``pytest`` at module level but its helpers take
    explicit URL/mount args (no fixture deps), so they are importable from a
    plain script context. We add ``tests/`` to sys.path and import lazily so
    the script can also print usage/--dry-run without touching them.
    """
    sys.path.insert(0, str(REPO_ROOT / "tests"))
    from e2e_real.test_reasoning_loop_ab import (  # noqa: PLC0415
        _run_catalog_floor,
        _run_reasoning_loop,
        _write_ab_report,
    )

    return _run_catalog_floor, _run_reasoning_loop, _write_ab_report


# ---------------------------------------------------------------------------
# Environment / target reachability (no pytest fixtures)
# ---------------------------------------------------------------------------

def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return _run(["docker", "info"], timeout=5) == 0


def _run(cmd: list[str], timeout: int = 30) -> int:
    try:
        import subprocess

        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        ).returncode
    except (OSError, subprocess.TimeoutExpired):
        return 1


def _target_up(url: str) -> bool:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=5) as resp:
            return resp.status == 200
    except Exception:  # noqa: BLE001 - any failure means the target is down
        return False


def _docker_mount_dir() -> Path:
    """Provide a host dir safe for Docker bind mounts (mirror conftest)."""
    candidates = [Path("/var/tmp/secopent-ab"), REPO_ROOT / ".test-mounts"]
    for base in candidates:
        try:
            base.mkdir(parents=True, exist_ok=True)
            return base
        except OSError:
            continue
    raise RuntimeError("no writable bind-mount host dir for the A/B run")


# ---------------------------------------------------------------------------
# Decision criteria
# ---------------------------------------------------------------------------

def _compute_verdict(delta: int, cost_ratio: float | None) -> str:
    """Return RELEASE / FREEZE from the A/B criteria (spec section 10)."""
    if cost_ratio is None:
        return "FREEZE"
    if delta > 0 and cost_ratio < COST_RATIO_THRESHOLD:
        return "RELEASE"
    return "FREEZE"


# ---------------------------------------------------------------------------
# Real run
# ---------------------------------------------------------------------------

def _run_target(
    name: str,
    mounts: Path,
    run_floor,
    run_loop,
    proposer: str,
) -> dict:
    url = TARGET_URLS[name]
    if not _target_up(url):
        raise RuntimeError(
            f"target {name} ({url}) not reachable - start provisioning first"
        )
    t0 = time.monotonic()
    floor_observations, _candidates = run_floor(url, mounts)
    control_wall = time.monotonic() - t0

    t1 = time.monotonic()
    experiment = run_loop(url, mounts, proposer=proposer)
    experiment_wall = time.monotonic() - t1

    return {
        "control_observations": len(floor_observations),
        "control_wall_seconds": round(control_wall, 3),
        "experiment_oracle_confirmed": experiment.oracle_confirmed,
        "experiment_candidates": experiment.candidates,
        "false_positive_rate": (
            (experiment.refuted / experiment.candidates)
            if experiment.candidates
            else 0.0
        ),
        "cost_tokens": experiment.tokens_used,
        "wall_seconds": round(experiment_wall, 3),
        "approval_count": experiment.approval_count,
    }


def _aggregate(results: dict[str, dict]) -> dict:
    delta = sum(r["experiment_oracle_confirmed"] for r in results.values())
    total_tokens = sum(r["cost_tokens"] for r in results.values())
    experiment_wall = sum(r["wall_seconds"] for r in results.values())
    control_wall = sum(r["control_wall_seconds"] for r in results.values())
    total_candidates = sum(r["experiment_candidates"] for r in results.values())
    total_refuted = sum(
        round(r["false_positive_rate"] * r["experiment_candidates"])
        for r in results.values()
    )
    fpr = (total_refuted / total_candidates) if total_candidates else 0.0
    approvals = sum(r["approval_count"] for r in results.values())
    cost_ratio = (
        (experiment_wall / control_wall) if control_wall else None
    )
    return {
        "oracle_confirmed_delta": delta,
        "false_positive_rate": round(fpr, 4),
        "cost_tokens": total_tokens,
        "wall_seconds": round(experiment_wall, 3),
        "approval_count": approvals,
        "cost_ratio": (
            None if cost_ratio is None else round(cost_ratio, 3)
        ),
        "verdict": _compute_verdict(delta, cost_ratio),
    }


def _print_table(results: dict[str, dict], agg: dict) -> None:
    width = 88
    sep = "-" * width

    print(sep)
    print("ReasoningLoop A/B - decision criteria (spec section 10)")
    print(sep)
    header = (
        f"{'target':<12}{'delta':>6}{'FP-rate':>9}{'cost_tok':>10}"
        f"{'wall_s':>9}{'approx':>8}{'cost_ratio':>11}"
    )
    print(header)
    print(sep)
    for name, r in results.items():
        fp = f"{r['false_positive_rate']:.3f}"
        print(
            f"{name:<12}{r['experiment_oracle_confirmed']:>6}{fp:>9}"
            f"{r['cost_tokens']:>10}{r['wall_seconds']:>9}"
            f"{r['approval_count']:>8}{'':>11}"
        )
    print(sep)
    cr = "n/a" if agg["cost_ratio"] is None else f"{agg['cost_ratio']:.3f}"
    print(
        f"{'AGGREGATE':<12}{agg['oracle_confirmed_delta']:>6}"
        f"{agg['false_positive_rate']:>9.3f}{agg['cost_tokens']:>10}"
        f"{agg['wall_seconds']:>9}{agg['approval_count']:>8}{cr:>11}"
    )
    print(sep)
    print(f"Cost-ratio threshold: {COST_RATIO_THRESHOLD:.1f}x "
          f"(experiment wall / control wall)")
    print(f"RELEASE requires: oracle_confirmed_delta > 0 AND cost_ratio < "
          f"{COST_RATIO_THRESHOLD:.1f}x")
    print(f"VERDICT: {agg['verdict']}")
    if agg["false_positive_rate"] > 0:
        print("NOTE: FP-rate > 0 - if it exceeds the control by >1.5x, "
              "advisory review is recommended (does not change the CI verdict).")
    print(sep)


def _print_dry_run(targets: tuple[str, ...], proposer: str, out: Path) -> None:
    print("Dry run (no execution) - A/B plan for the ReasoningLoop (v0.7.9)")
    print("=" * 88)
    print(f"Targets : {', '.join(targets)}")
    print(f"Proposer: {proposer}")
    print(f"Out     : {out}")
    print(f"Docker  : {'available' if _docker_available() else 'NOT available'}")
    for name in targets:
        up = _target_up(TARGET_URLS[name])
        print(f"  {name:<12} {TARGET_URLS[name]:<25} "
              f"{'reachable' if up else 'NOT reachable'}")
    print("=" * 88)
    print("Decision-criteria table (filled after a real run):")
    print(
        f"{'target':<12}{'delta':>6}{'FP-rate':>9}{'cost_tok':>10}"
        f"{'wall_s':>9}{'approx':>8}{'cost_ratio':>11}"
    )
    for name in targets:
        print(
            f"{name:<12}{'':>6}{'':>9}{'':>10}{'':>9}{'':>8}{'':>11}"
        )
    print("=" * 88)
    print("VERDICT: pending (needs Docker + live targets + LLM key)")
    print("To run: py -3.12 scripts/ab_reasoning_loop.py")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ab_reasoning_loop",
        description="Run the ReasoningLoop A/B across provisioned targets and "
                    "print the decision-criteria table + aggregated JSON.",
    )
    parser.add_argument(
        "--targets",
        nargs="+",
        choices=TARGETS_DEFAULT,
        default=list(TARGETS_DEFAULT),
        help=f"targets to test (default: {', '.join(TARGETS_DEFAULT)})",
    )
    parser.add_argument(
        "--proposer",
        choices=("real", "mock"),
        default="real",
        help="proposer arm to run (default: real)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help=f"output JSON path (default: {DEFAULT_OUT})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the plan + criteria table template without executing",
    )
    args = parser.parse_args(argv)

    if args.dry_run:
        _print_dry_run(tuple(args.targets), args.proposer, args.out)
        return 0

    if not _docker_available():
        print("ERROR: docker is not available (needed by RealScanRunner).")
        return 2

    run_floor, run_loop, write_report = _ensure_ab_helpers()
    mounts = _docker_mount_dir()

    results: dict[str, dict] = {}
    for name in args.targets:
        try:
            results[name] = _run_target(
                name, mounts, run_floor, run_loop, args.proposer
            )
        except RuntimeError as exc:
            print(f"ERROR: {exc}")
            return 3

    agg = _aggregate(results)
    report = {
        "date": datetime.datetime.now(datetime.UTC).isoformat(),
        "proposer": args.proposer,
        "results": results,
        "aggregate": agg,
    }
    path = write_report(report)
    _print_table(results, agg)
    print(f"Report written: {path}")
    # Exit 0 even on FREEZE: this is research, not a CI gate.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
