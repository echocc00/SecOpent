"""Check cloud host deployment readiness for SecOpent."""
from __future__ import annotations
import paramiko
import sys

HOST = "8.133.200.235"
USER = "root"
PASSWORD = "REDACTED_CLOUD_CREDENTIAL"

CHECKS = """
echo "===OS==="
cat /etc/os-release 2>/dev/null | head -5
echo "===KERNEL==="
uname -a
echo "===ARCH==="
uname -m
echo "===CPU==="
nproc
echo "===CPU MODEL==="
grep "model name" /proc/cpuinfo | head -1
echo "===RAM==="
free -h
echo "===DISK==="
df -h / /home 2>/dev/null | head -5
echo "===DOCKER==="
docker --version 2>&1 || echo "docker NOT installed"
docker compose version 2>&1 || echo "docker compose NOT installed"
echo "===PYTHON==="
python3 --version 2>&1
python3 -c "import sys; print(sys.executable)" 2>&1
echo "===GIT==="
git --version 2>&1
echo "===NETWORK PUBLIC IP==="
curl -s --max-time 5 ifconfig.me 2>&1 || curl -s --max-time 5 ipinfo.io/ip 2>&1 || echo "no public ip"
echo ""
echo "===PORTS LISTENING==="
ss -tlnp 2>/dev/null | head -15 || netstat -tlnp 2>/dev/null | head -15
echo "===FIREWALL==="
ufw status 2>&1 | head -5 || iptables -L -n 2>&1 | head -10
echo "===VIRTUALIZATION==="
systemd-detect-virt 2>&1 || echo "unknown"
echo "===CONTAINER RUNTIME==="
which docker podman containerd 2>&1
echo "===SECURITY==="
id
echo "===DNS==="
cat /etc/resolv.conf 2>/dev/null | head -3
echo "===REACHABILITY OSV==="
curl -s --max-time 5 -o /dev/null -w "%{http_code}" https://api.osv.dev/v1/query 2>&1 || echo "OSV unreachable"
echo ""
echo "===REACHABILITY GITHUB==="
curl -s --max-time 5 -o /dev/null -w "%{http_code}" https://github.com 2>&1 || echo "github unreachable"
echo ""
echo "===REACHABILITY DOCKER HUB==="
curl -s --max-time 5 -o /dev/null -w "%{http_code}" https://registry-1.docker.io/v2/ 2>&1 || echo "docker hub unreachable"
echo ""
"""


def main() -> int:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(HOST, username=USER, password=PASSWORD, timeout=15)
    except Exception as exc:
        print(f"SSH connect failed: {exc}", file=sys.stderr)
        return 1
    stdin, stdout, stderr = client.exec_command(CHECKS, timeout=60)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    print(out)
    if err.strip():
        print("===STDERR===", file=sys.stderr)
        print(err, file=sys.stderr)
    client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
