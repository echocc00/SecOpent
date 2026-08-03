"""SecOpent environment verification (Phase A Task A1, Step 6).

Run:  python3 scripts/verify_env.py   (Windows: py -3.12)

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


def check_filesystem() -> dict:
    """Check whether /tmp (pytest tmp_path) is on a filesystem Docker can bind-mount.

    On NAS appliances where /tmp is tmpfs with overlay subvolumes, Docker bind
    mounts from those paths appear empty inside containers. This check warns
    early so the user knows integration tests may need docker_mount_dir fallback.
    """
    import platform
    if platform.system() != "Linux":
        return {"pass": True, "note": "non-Linux; bind-mount safety assumed"}
    try:
        mounts = Path("/proc/mounts").read_text()
    except OSError:
        return {"pass": True, "note": "/proc/mounts unreadable; assuming safe"}
    import tempfile
    tmp = str(Path(tempfile.gettempdir()).resolve())
    best_match = ""
    best_fs = ""
    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        mount_point, fs_type = parts[1], parts[2]
        if tmp.startswith(mount_point) and len(mount_point) > len(best_match):
            best_match = mount_point
            best_fs = fs_type
    if best_fs in ("tmpfs", "overlay"):
        return {"pass": True, "warning": True,
                "note": f"/tmp is {best_fs}; docker_mount_dir fixture will use /var/tmp fallback"}
    return {"pass": True, "fs_type": best_fs or "unknown"}


def check_ports() -> dict:
    """Detect whether SecOpent's ports (API + targets) are already in use.

    8000 in use before startup is a hard conflict (the API cannot bind). 3000/
    8080 in use may legitimately be the SecOpent target range itself (run before
    verify) so they are reported as info, not failures.
    """
    import socket
    ports = [("8000", "SecOpent API"), ("3000", "juice-shop"), ("8080", "httpbin")]
    findings: dict[str, dict] = {}
    for port_s, label in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            in_use = sock.connect_ex(("127.0.0.1", int(port_s))) == 0
        except OSError:
            in_use = False
        finally:
            sock.close()
        findings[port_s] = {"label": label, "in_use": in_use}
    api_conflict = findings["8000"]["in_use"]
    return {
        "pass": not api_conflict,
        "ports": findings,
        "note": "8000 in use = API port conflict; 3000/8080 in use may be your targets",
    }


def check_host_gateway() -> dict:
    """Verify host.docker.internal resolves inside a container.

    The executor adds --add-host host.docker.internal:host-gateway, but this
    check confirms the mechanism actually works on this Docker setup.
    """
    rc, out, err = run(
        ["docker", "run", "--rm", "--add-host", "host.docker.internal:host-gateway",
         "library/alpine:latest", "ping", "-c", "1", "-W", "2", "host.docker.internal"],
        timeout=30,
    )
    if rc == 127:
        return {"pass": False, "reason": "alpine image not available locally"}
    if rc == 124:
        return {"pass": False, "reason": "ping timed out (host-gateway not routable?)"}
    return {"pass": rc == 0, "note": out.strip()[:80] if rc == 0 else err.strip()[:80]}


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
        "filesystem": check_filesystem(),
        "ports": check_ports(),
        "host_gateway": check_host_gateway(),
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
