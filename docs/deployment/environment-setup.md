# Environment Setup (Phase A Task A1)

SecOpent Phase A requires Docker + tools + targets + self-hosted Interactsh + LLM.
This guide covers local Windows + Docker Desktop setup (Linux/macOS analogous).

## Prerequisites

- **Docker Desktop** (Windows/Mac/Linux) with WSL2 backend on Windows
- **Python 3.11+** (3.12 recommended)
- **Git**
- **Public internet** (GitHub/OSV reachable; Docker Hub via China mirror)
- **LLM API key** (MiniMax/DeepSeek/Qwen/OpenAI - any OpenAI-compatible)

## 1. Docker Desktop + China registry mirror

Docker Hub (`registry-1.docker.io`) is blocked from CN networks. Configure
registry mirrors in `~/.docker/daemon.json`:

```json
{
  "builder": { "gc": { "defaultKeepStorage": "20GB", "enabled": true } },
  "experimental": false,
  "registry-mirrors": [
    "https://docker.1panel.live",
    "https://docker.m.daocloud.io"
  ]
}
```

**Restart Docker Desktop** (system tray → Restart) for `registry-mirrors` to take effect.

Verify:
```bash
docker --version                      # Docker 29.x
docker compose version                # Compose v5.x
docker pull projectdiscovery/nuclei:latest   # should succeed via mirror
```

## 2. SecOpent repo + Python deps

```bash
cd SecOpent   # your clone path
python3 -m pip install -e ".[dev]"
python3 -m pytest -q                 # 806 tests should pass (V1 Beta)
```

## 3. Tool images (17 adapters)

Image catalog: `src/secopent/infrastructure/adapters/image_catalog.py`.

Pull core images (asset/web/network + targets + interactsh):
```bash
for img in projectdiscovery/subfinder projectdiscovery/httpx \
           projectdiscovery/naabu projectdiscovery/katana \
           projectdiscovery/nuclei hahwul/dalfox instrumentisto/nmap \
           bkimminich/juice-shop kennethreitz/httpbin \
           projectdiscovery/interactsh-server; do
  docker pull $img:latest
done
```

Cloud adapters (Prowler/Trivy/kube-bench/checkov/ScoutSuite) + ZAP/RESTler/Schemathesis
pulled in their respective Phase A tasks (A2/A3) as needed.

**Digest pinning**: after pulling, record digests in `image_catalog.py`:
```bash
docker images --digests | grep projectdiscovery/nuclei
# fill IMAGE_CATALOG["nuclei"].digest = "sha256:..."
```

## 4. E2E target ranges

```bash
cd SecOpent   # your clone path
docker compose -f scripts/provision/docker-compose.targets.yml up -d
```

Verify:
```bash
curl -s http://localhost:3000 | head -1   # Juice Shop
curl -s http://localhost:8080/get          # httpbin
```

Stop: `docker compose -f scripts/provision/docker-compose.targets.yml down`

## 5. Self-hosted Interactsh OOB

> 完整部署 + 验证指南见 [`docs/deployment/interactsh.md`](interactsh.md)。
> 本节为快速启动；端口订正、HTTPS 限制、公网部署等细节见该文档。

```bash
docker compose -f scripts/provision/docker-compose.interactsh.yml up -d
```

DNS setup (intranet testing):
- Add to `C:\Windows\System32\drivers\etc\hosts`: `127.0.0.1  oast.local`
- For wildcard `*.oast.local`, use a local DNS resolver or configure system DNS to 127.0.0.1:5300

Verify (HTTP callback endpoint; 8444/HTTPS is disabled for `oast.local` intranet):
```bash
docker ps | grep secopent-interactsh
curl -s http://localhost:8081/ | head -1   # -> <h1> Interactsh Server </h1>
```

Set the env var so SecOpent uses the real transport:
```bash
export SECOPTENT_INTERACTSH_SERVER_URL=http://localhost:8081
```

Public deployment (later): point a real domain's NS to this host, use `-domain <your.domain>`.

## 6. LLM backend (remote, OpenAI-compatible)

Config: `config/llm.yaml`. Default: MiniMax.

Set API key env var:
```bash
# Windows (PowerShell, persistent)
setx MINIMAX_API_KEY "your-key-here"
# Or Git Bash session
export MINIMAX_API_KEY="your-key-here"
```

Alternative providers (uncomment in `config/llm.yaml`):
- DeepSeek: `DEEPSEEK_API_KEY`, endpoint `https://api.deepseek.com/v1`, model `deepseek-chat`
- Qwen: `DASHSCOPE_API_KEY`, endpoint `https://dashscope.aliyuncs.com/compatible-mode/v1`, model `qwen-plus`
- OpenAI: `OPENAI_API_KEY`, endpoint `https://api.openai.com/v1`, model `gpt-4o-mini`

Local model (Ollama) is reserved as an interface for later (Phase B+); not configured in Phase A.

## 7. Verify everything

```bash
python3 scripts/verify_env.py
```

Expected: all PASS (Docker / images / targets / interactsh / llm).

LLM check passes if `config/llm.yaml` exists + API key env var set. Real LLM call
is tested in Phase A Task A6.

## Troubleshooting

### Docker pull fails (dialing registry-1.docker.io)
- daemon.json `registry-mirrors` not applied → restart Docker Desktop
- Mirror down → try the other mirror (1panel.live / daocloud.io)

### Target not reachable
- `docker ps` check container running
- Port conflict (3000/8080 used) → edit `docker-compose.targets.yml` ports

### Interactsh OOB not capturing
- DNS: `*.oast.local` must resolve to 127.0.0.1 (hosts file or local DNS)
- Firewall: ports 5300/8081/8444/2525 open

### LLM check fails
- API key env var not set → `echo $MINIMAX_API_KEY`
- Endpoint wrong → check `config/llm.yaml` provider section
- Network → `curl https://api.minimax.chat/v1/models -H "Authorization: Bearer $MINIMAX_API_KEY"`

### Tests fail after env change
- `python3 -m pytest -q` should stay 806 passed
- If new failures, check architecture boundaries (`tests/test_architecture_boundaries.py`)
