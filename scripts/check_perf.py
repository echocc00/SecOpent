#!/usr/bin/env python
"""Compare current perf benchmarks against the committed baseline (T12 / §⑧).

Runs ``pytest -m perf --benchmark-json`` and compares each benchmark's mean to
``benchmarks/baseline.json``. WARNS (exit 0) when any benchmark regresses by more
than ``--threshold`` (default 20%); exits 1 only on a hard error (missing
baseline, or the benchmarks failed to run). A warning never fails CI - timings
are hardware-dependent, so this is a tripwire for the same runner class, not a
portable gate.

Usage:
    python scripts/check_perf.py [--threshold 0.20] [--baseline benchmarks/baseline.json]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = REPO_ROOT / "benchmarks" / "baseline.json"


def _means(path: str | Path) -> dict[str, float]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {b["name"]: float(b["stats"]["mean"]) for b in data["benchmarks"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threshold", type=float, default=0.20,
                        help="regression threshold as a fraction (default 0.20 = 20%)")
    parser.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    args = parser.parse_args(argv)

    if not Path(args.baseline).exists():
        print(f"error: baseline not found: {args.baseline}")
        return 1
    baseline = _means(args.baseline)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        current_path = tmp.name
    proc = subprocess.run(  # noqa: S603 - fixed argv, not a shell
        [sys.executable, "-m", "pytest", "-m", "perf", "tests/perf/test_perf.py",
         f"--benchmark-json={current_path}", "-q"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        print("error: perf benchmarks failed to run")
        print(proc.stdout[-2000:])
        print(proc.stderr[-1000:])
        return 1
    current = _means(current_path)

    print(f"{'benchmark':45} {'baseline(ms)':>14} {'current(ms)':>14} {'delta':>9}")
    regressions: list[tuple[str, float]] = []
    for name, base_mean in sorted(baseline.items()):
        cur = current.get(name)
        if cur is None:
            print(f"{name:45} {'<missing in current run>':>28}")
            continue
        delta = (cur - base_mean) / base_mean if base_mean else 0.0
        flag = "  <-- regression" if delta > args.threshold else ""
        print(f"{name:45} {base_mean * 1000:14.3f} {cur * 1000:14.3f} {delta * 100:8.1f}%{flag}")
        if delta > args.threshold:
            regressions.append((name, delta))

    if regressions:
        print(f"\nWARNING: {len(regressions)} benchmark(s) regressed "
              f"> {args.threshold * 100:.0f}%:")
        for name, delta in regressions:
            print(f"  - {name}: +{delta * 100:.1f}%")
        print("(timings are hardware-dependent; treat as a tripwire, not a hard gate)")
    else:
        print("\nOK: no benchmark regressed beyond the threshold")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
