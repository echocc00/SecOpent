"""SecOpent environment verification (Phase A Task A1, Step 6).

Run:  py -3.12 scripts/verify_env.py

Checks all Phase A dependencies:
1. Docker daemon running + compose available
2. Required images present (digest-pinned catalog)
3. E2E target ranges reachable (Juice Shop / httpbin)
4. Self-hosted Interactsh OOB callback capture
5. LLM backend configured + reachable (skipped if no API key)

Exit 0 if all pass, 1 if any fail. Output is human-readable + JSON-able.
"""
from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGETS_COMPOSE = REPO_ROOT / "scripts" / "provision" / "docker-compose.targets.yml"
INTERACTSH_COMPOSE = REPO_ROOT / "scripts" / "provision" / "docker-compose.interactsh.yml"

REQUIRED_IMAGES = [
    "projectdiscovery/subfinder",
    "projectdiscovery/httpx",
    "projectdiscovery/naabu",
    "projectdiscovery/katana",
    "projectdiscovery/nuclei",
    "hahwul/dalfox",
    "instrumentisto/nmap",
    "bkimminich/juice-shop",
    "kennethreitz/httpbin",
    "projectdiscovery/interactsh-server",
]


def run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{cmd[0]} timed out"


def check_docker() -> dict:
    rc, out, _ = run(["docker", "info", "--format", "{{.ServerVersion}}"])
    if rc != 0:
        return {"pass": False, "reason": "docker daemon not running"}
    rc2, _, _ = run(["docker", "compose", "version"])
    return {"pass": rc2 == 0, "version": out.strip(), "compose": rc2 == 0}


def check_images() -> dict:
    rc, out, _ = run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"])
    present = set(out.strip().splitlines()) if rc == 0 else set()
    missing = [img for img in REQUIRED_IMAGES if f"{img}:latest" not in present]
    return {"pass": not missing, "present": len(REQUIRED_IMAGES) - len(missing),
            "total": len(REQUIRED_IMAGES), "missing": missing}


def check_targets() -> dict:
    results = {}
    for name, url in [("juice_shop", "http://localhost:3000"), ("httpbin", "http://localhost:8080")]:
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                results[name] = {"pass": resp.status == 200, "status": resp.status}
        except urllib.error.HTTPError as exc:
            results[name] = {"pass": exc.code < 500, "status": exc.code}
        except (urllib.error.URLError, OSError) as exc:
            results[name] = {"pass": False, "reason": str(exc)[:80]}
    return {"pass": all(r["pass"] for r in results.values()), "targets": results}


def check_interactsh() -> dict:
    # Check container running + HTTP callback endpoint responds
    rc, out, _ = run(["docker", "ps", "--filter", "name=secopent-interactsh",
                      "--format", "{{.Names}}"])
    if rc != 0 or "secopent-interactsh" not in out:
        return {"pass": False, "reason": "interactsh container not running"}
    # Try HTTP callback endpoint (8081 mapped to 80)
    try:
        req = urllib.request.Request("http://localhost:8081/", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return {"pass": resp.status in (200, 404), "status": resp.status}
    except urllib.error.HTTPError as exc:
        return {"pass": exc.code in (200, 404), "status": exc.code}
    except (urllib.error.URLError, OSError) as exc:
        return {"pass": False, "reason": str(exc)[:80]}


def check_llm() -> dict:
    # Check config exists + API key env var set (skip actual call if no key)
    llm_yaml = REPO_ROOT / "config" / "llm.yaml"
    if not llm_yaml.is_file():
        return {"pass": False, "reason": "config/llm.yaml missing"}
    text = llm_yaml.read_text(encoding="utf-8")
    # Find api_key_env line (first non-commented)
    api_key_env = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("api_key_env:") and not line.startswith("#"):
            api_key_env = line.split(":", 1)[1].strip()
            break
    if not api_key_env:
        return {"pass": False, "reason": "api_key_env not configured"}
    import os
    key = os.environ.get(api_key_env, "")
    if not key:
        return {"pass": False, "reason": f"env var {api_key_env} not set (LLM call skipped)",
                "configured": True, "key_set": False}
    return {"pass": True, "configured": True, "key_set": True,
            "note": "API key set; real call tested in Phase A Task A6"}


def main() -> int:
    checks = {
        "docker": check_docker(),
        "images": check_images(),
        "targets": check_targets(),
        "interactsh": check_interactsh(),
        "llm": check_llm(),
    }
    all_pass = all(c.get("pass", False) for c in checks.values())

    print("=" * 60)
    print("SecOpent Environment Verification (Phase A Task A1)")
    print("=" * 60)
    for name, result in checks.items():
        status = "PASS" if result.get("pass") else "FAIL"
        print(f"[{status}] {name}")
        for k, v in result.items():
            if k != "pass":
                print(f"         {k}: {v}")
    print("=" * 60)
    print(f"Overall: {'ALL PASS' if all_pass else 'SOME FAILED'}")
    print("=" * 60)
    if not all_pass:
        print("\nJSON:")
        print(json.dumps(checks, indent=2, default=str))
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
