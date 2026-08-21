"""SecOpent ReasoningLoop A/B — NAS adapter (mock stage, v0.7.9).

Runs the mock-LLM A/B on the NAS isolated repo against a LIVE target,
adapting the two dind constraints of the stock batch runner
(``scripts/ab_reasoning_loop.py``):

1. Target URL must be the NAS host IP, not ``localhost``: the control arm's
   nuclei container runs on Docker's default bridge network, so ``localhost``
   would be the container itself. We resolve it from the env var
   ``AB_TARGET_URL`` (default ``http://192.168.2.18:3000``) and hand that URL
   to both arms (nuclei ``-u`` AND the DIFF_SEMANTIC oracle requests).
2. The docker_mount_dir (nuclei template host dir) must be a HOST-shared
   absolute path so the dind nuclei container can bind-mount it. This adapter
   uses ``AB_WORK_MOUNTS`` (default the host dir ``/volume1/soft/secopent-ab/
   work-mounts``) which the driver container binds at the SAME absolute path.

This script reuses the importable standalone helpers
``_run_catalog_floor`` / ``_run_reasoning_loop`` / ``_write_ab_report`` from
``tests/e2e_real/test_reasoning_loop_ab_mock.py`` (mock proposer, so the
experiment arm spends no LLM tokens — only live traffic is the DIFF_SEMANTIC
oracle against the target).

Run inside the driver container (uses the repo's installed package):
    python scripts/ab_reasoning_loop_nas.py [--target juice_shop] [--report PATH]
"""
from __future__ import annotations

import argparse
import datetime
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = REPO_ROOT / "test-results" / "reasoning_loop_ab_nas.json"

TARGETS = {
    "juice_shop": os.environ.get("AB_TARGET_URL", "http://192.168.2.18:3000"),
    "cr_api": os.environ.get("AB_CR_API_URL", "http://192.168.2.18:8000"),
    "vulhub": os.environ.get("AB_VULHUB_URL", "http://192.168.2.18:8081"),
}
WORK_MOUNTS = Path(
    os.environ.get("AB_WORK_MOUNTS", "/volume1/soft/secopent-ab/work-mounts")
)


def _load_helpers(proposer: str):
    sys.path.insert(0, str(REPO_ROOT / "tests"))
    if proposer == "mock":
        # helper module: import the mock A/B helpers (control + experiment + report)
        from e2e_real.test_reasoning_loop_ab_mock import (  # noqa: PLC0415
            _run_catalog_floor,
            _run_reasoning_loop,
            _write_ab_report,
        )
    else:
        from e2e_real.test_reasoning_loop_ab import (  # noqa: PLC0415
            _run_catalog_floor,
            _run_reasoning_loop,
            _write_ab_report,
        )

    return _run_catalog_floor, _run_reasoning_loop, _write_ab_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ab_reasoning_loop_nas")
    parser.add_argument(
        "--target", choices=tuple(TARGETS), default="juice_shop"
    )
    parser.add_argument(
        "--proposer", choices=("mock", "real"), default="mock"
    )
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args(argv)

    run_floor, run_loop, write_report = _load_helpers(args.proposer)
    url = TARGETS[args.target]
    mounts = WORK_MOUNTS

    print(f"proposer      : {args.proposer}")
    print(f"target        : {args.target}")
    print(f"url           : {url}")
    print(f"work mount dir: {mounts}")

    floor_observations, floor_candidates = run_floor(url, mounts)
    summary = run_loop(url, mounts, proposer=args.proposer)

    report = {
        "date": datetime.date.today().isoformat(),
        "target": args.target,
        "url": url,
        "proposer": args.proposer,
        "catalog_floor": {
            "observation_count": len(floor_observations),
            "candidate_count": len(floor_candidates),
        },
        "reasoning_loop": {
            "oracle_confirmed": summary.oracle_confirmed,
            "refuted": summary.refuted,
            "candidates": summary.candidates,
            "steps_run": summary.steps_run,
            "tokens_used": summary.tokens_used,
            "approval_count": summary.approval_count,
            "wall_seconds": round(summary.wall_seconds, 3),
            "final_phase": summary.final_phase,
        },
    }
    path = write_report(report)
    print(f"Report written: {path}")
    print(f"  floor obs={len(floor_observations)} candidates={len(floor_candidates)}")
    print(f"  loop oracle_confirmed={summary.oracle_confirmed} "
          f"refuted={summary.refuted} candidates={summary.candidates}")
    print(f"  loop steps={summary.steps_run} tokens={summary.tokens_used} "
          f"approvals={summary.approval_count} final_phase={summary.final_phase}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
