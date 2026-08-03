# peer-worker entrypoint: read /exchange/input.json, run strix, leave
# artifacts under /exchange/out/. Exit code mirrors strix's.
import json
import subprocess
import sys
from pathlib import Path

EXCHANGE = Path("/exchange")
OUT = EXCHANGE / "out"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    payload = json.loads((EXCHANGE / "input.json").read_text(encoding="utf-8"))
    targets = payload["targets"]
    instruction = payload.get("instruction", "")
    cmd = ["strix"]
    for target in targets:
        cmd += ["--target", target]
    if instruction:
        cmd += ["--instruction", instruction]
    cmd += ["--run-name", str(payload["run_id"])]
    proc = subprocess.run(cmd, cwd=str(EXCHANGE), check=False)  # noqa: S603
    # strix writes strix_runs/<run-name>/; lift the key artifacts to out/
    run_dir = EXCHANGE / "strix_runs" / str(payload["run_id"])
    for name in ("vulnerabilities.json", "run.json"):
        src = run_dir / name
        if src.exists():
            (OUT / name).write_bytes(src.read_bytes())
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
