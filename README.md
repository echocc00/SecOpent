# SecOpent

Catalog-driven, agent-native **authorized** pentest workbench. FastAPI backend + React Case Studio. The LLM only ever *proposes*; the deterministic layer + humans decide (scope, approval, signing, findings, publish).

> Status: **v1.1-stable** track (P3). Design: `sepcs/2026-07-25-catalog-driven-agent-workbench-design.md`.

## Quick start

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

- [Core boundaries](docs/architecture/core-boundaries.md) · [Knowledge layer](docs/architecture/knowledge-layer.md) · [Verification / oracle](docs/architecture/verification.md) · [Peer agents](docs/architecture/peer-agents.md)
- [Adapter pack (four domains)](docs/adapters/README.md) · [Subprocess executor](docs/architecture/subprocess-executor.md)
- [AppModel schema](docs/appmodel/schema.md) · [Model-driven logic](docs/architecture/model-driven-logic.md) · [Web Case Studio](docs/web/case-studio.md)
- [YAML case DSL](docs/cases/yaml-dsl.md) · [Interfaces (MCP/CLI/API/Web)](docs/architecture/interfaces.md) · [API (OpenAPI)](docs/api/openapi.yaml)
- [STRIDE threat model](docs/security/threat-model.md)

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
