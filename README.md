# SecOpent

Catalog-driven, agent-native **authorized** pentest workbench. FastAPI backend + React Case Studio. The LLM only ever *proposes*; the deterministic layer + humans decide (scope, approval, signing, findings, publish).


[![Latest Release](https://img.shields.io/github/v/release/echocc00/SecOpent?display_name=tag&style=flat-square)](https://github.com/echocc00/SecOpent/releases/latest)
[![License](https://img.shields.io/github/license/echocc00/SecOpent?style=flat-square)](./LICENSE)
[![License Check](https://img.shields.io/github/actions/workflow/status/echocc00/SecOpent/license-check.yml?branch=master&style=flat-square&label=license)](https://github.com/echocc00/SecOpent/actions/workflows/license-check.yml)

> 💼 **商业授权 / Commercial licensing**
>
> 本项目以开源协议发布(详见 [LICENSE](./LICENSE)),你可自由用于个人/企业内部项目。
> 若你希望用于**对外商业产品 / SaaS / 销售**并需要:
> - 作者署名可移除 / 不想被认出来源
> - 闭源分发 / 不公开修改
> - 长期维护支持 / 私有定制
> - 法律意见 / 合规背书
>
> 请通过以下方式联系作者协商**独立商业授权**:
> - GitHub: [@echocc00](https://github.com/echocc00)
> - 项目主页 Issues / Discussions(按项目)
>
> 大部分项目 24 小时内响应,首次咨询免费。
>
> *(本说明不构成法律意见,具体权利义务以 [LICENSE](./LICENSE) 文本为准。)*

---

> Status: **v1.1.1-stable** track (P3). Design: `sepcs/2026-07-25-catalog-driven-agent-workbench-design.md`.

## Quick start
> 📘 **5-minute getting-started**: see [`docs/getting-started.md`](docs/getting-started.md).


```bash
python3 -m pip install -e ".[dev]"
python3 -m pytest -q                 # full suite (should be green)

# API (dev) on :8000
python3 -m uvicorn secopent.interfaces.api.main:create_app --factory --port 8000

# Web Case Studio (dev) on :5173, proxies /api -> :8000
cd src/secopent/interfaces/web && npm install && npm run dev

# Production single-port build (SPA + API on :8000)
bash scripts/build_web.sh
```

A default TestCatalog (OWASP WSTG + CIS baseline) is seeded at startup, so plan generation works out of the box.

> **Windows**: replace `python3` with `py -3.12` in the commands above.

## Guides (start here)

| Guide | For | Covers |
|---|---|---|
| [用户手册 User Manual](docs/user-manual.md) | operators | install, run a full authorized assessment, approval, findings, reports, CLI |
| [Case Studio 建模指南](docs/case-studio-guide.md) | modelers | AppModel modeling, 5 logic-test classes, signing/release, drift detection |
| [Adapter 开发指南](docs/adapter-guide.md) | developers | adapter contract (manifest + digest-pin + parser + fixtures), add a new adapter |
| [生产部署 Deployment](docs/deployment.md) | ops | build, config, key management, SQLite→PG, backup, logging/audit |

Environment prep (Docker, tool images, target ranges, Interactsh OOB, LLM key): [docs/deployment/environment-setup.md](docs/deployment/environment-setup.md).

## Reference docs

- [Core boundaries](docs/architecture/core-boundaries.md) · [Knowledge layer](docs/architecture/knowledge-layer.md) · [Verification / oracle](docs/architecture/verification.md) · [Peer agents](docs/architecture/peer-agents.md) · [Attack chain](docs/architecture/attack-chain.md)
- [Adapter pack (four domains)](docs/adapters/README.md) · [Subprocess executor](docs/architecture/subprocess-executor.md)
- [AppModel schema](docs/appmodel/schema.md) · [Model-driven logic](docs/architecture/model-driven-logic.md) · [Web Case Studio](docs/web/case-studio.md)
- [YAML case DSL](docs/cases/yaml-dsl.md) · [Interfaces (MCP/CLI/API/Web)](docs/architecture/interfaces.md) · [API (OpenAPI)](docs/api/openapi.yaml)
- [STRIDE threat model](docs/security/threat-model.md)
- [Checkpoint / Preflight / Deliverables](docs/architecture/checkpoint-preflight.md)

## Milestones

- **M0** — foundation + deterministic spine (projects/scope/assessment/audit, PolicyEngine, SQLite WAL, Repository contract)
- **M1** — knowledge layer + 17 adapters across asset/web/network/cloud, CoverageMatrix, signed update bundles, coverage gate
- **M2** — verification + case engine (oracle N/N, YAML case DSL no-eval interpreter, seccomp sandbox, three-layer evidence + redaction)
- **M3** — model-driven logic testing (signed AppModel, OpenAPI/Postman/traffic import + Ed25519 signing, five-class logic generator, drift, ModelRegistry)
- **M4** — agent interface + orchestration + report (Planner DAG, Orchestrator job lease + retry, ReportRenderer + completeness gate, MCP tools, FastAPI + SSE, CLI)
- **M5** — security hardening (ScopeEnforcer 10-step chain, signed ExecutionPermit, SecretStore, signed AuditChain, EmergencyStop, RemoteModelGateway, PromptInjectionGuard, scoped egress, PG contract, STRIDE, CI)
- **P3 (v1.1)** — default catalog seed, 3 LLM call points (propose-only), perf tuning, this doc set, production hardening (key rotation, audit HMAC, structured logging, backup)

## License

Apache-2.0. See [LICENSE](LICENSE).
