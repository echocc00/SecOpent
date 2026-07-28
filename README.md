# SecOpent

Catalog-driven Agent-native authorized pentest workbench.

> Status: **V1 Beta** (M0-M5 complete). Foundation + deterministic spine ✅; knowledge layer + four-domain adapter pack ✅; verification + case engine ✅; model-driven logic testing ✅; agent interface + orchestration + report ✅; security hardening (ScopeEnforcer 10-step chain + signed ExecutionPermit + SecretStore + signed AuditChain + EmergencyStop + RemoteModelGateway + PromptInjectionGuard + scoped egress + PG contract + 14 mandatory security conditions + STRIDE + CI) ✅.
> Design: see `sepcs/2026-07-25-catalog-driven-agent-workbench-design.md`.

## Milestones

- **M0** — foundation + deterministic spine (projects/scope/assessment/audit, PolicyEngine, SQLite WAL, Repository contract)
- **M1** — knowledge layer + adapter pack (TestCatalog, CoverageMatrix, Intel + provenance, signed update bundles, health monitor, 17 adapters across asset/web/network/cloud, coverage gate)
- **M2** — verification + case engine (oracle N/N via pentest-ai, VerificationMethodRegistry, canary tokens, self-hosted Interactsh OOB, ground-truth range regression, YAML case DSL with no-eval AST interpreter, static risk gate, case lifecycle, fixture runner, seccomp Python sandbox, three-layer evidence + redaction)
- **M3** — model-driven logic testing (signed AppModel state machine/invariants/fields/roles, OpenAPI/Postman/traffic import + human validation + Ed25519 signing, five-class logic test generator with idempotent signatures, drift detection, versioned ModelRegistry with per-assessment snapshots, model-generated case fast path)
- **M4** — agent interface + orchestration + report (AssetGraph relation table, deterministic finding fingerprint de-dup, Planner DAG from catalog+AppModel, single-machine Orchestrator with DB job lease + retry/deny classification, data-driven ReportRenderer with redaction + completeness gate, MCP tool registry with trust levels, FastAPI command/query API with idempotency + SSE, argparse CLI, asset/finding/report/job persistence, end-to-end assessment integration)
- **M5** — security hardening + Beta (ScopeEnforcer 10-step chain with DNS-rebinding defense, signed short-lived ExecutionPermit with nonce/replay rejection, reference-only SecretStore with encrypted-at-rest backend, signed AuditChain with rotation + GDPR redaction, EmergencyStop, RemoteModelGateway with LLM operational constraints, PromptInjectionGuard, scoped egress blocking metadata/DB/Docker-host, PostgreSQL contract, 14 mandatory security conditions, STRIDE threat model, CI)

## Docs

- [Core boundaries (M0)](docs/architecture/core-boundaries.md)
- [Knowledge layer](docs/architecture/knowledge-layer.md)
- [Adapter pack (four domains)](docs/adapters/README.md)
- [Verification / oracle](docs/architecture/verification.md)
- [YAML case DSL](docs/cases/yaml-dsl.md)
- [Model-driven logic](docs/architecture/model-driven-logic.md)
- [AppModel schema](docs/appmodel/schema.md)
- [Interfaces (MCP/CLI/API/Web)](docs/architecture/interfaces.md)
- [Web Case Studio](docs/web/case-studio.md)
- [API (OpenAPI)](docs/api/openapi.yaml)
- [STRIDE threat model](docs/security/threat-model.md)

## Quickstart

```bash
py -3.12 -m pip install -e ".[dev]"
py -3.12 -m pytest -q
```

## Web Case Studio (P1)

The React Case Studio lives in `src/secopent/interfaces/web`.

**Development** (API on :8000 + Vite dev server on :5173 with an `/api` proxy):

```bash
# Terminal 1 - API
py -3.12 -m uvicorn secopent.interfaces.api.main:create_app --factory --port 8000
# Terminal 2 - frontend
cd src/secopent/interfaces/web && npm install && npm run dev
# open http://localhost:5173
```

**Production** (build + serve the SPA and API together on :8000):

```bash
bash scripts/build_web.sh   # vite build, then uvicorn serves dist via SECOPTENT_WEB_DIST
# open http://localhost:8000 (SPA fallback for client-side routes; /api coexists)
```

**End-to-end** (Playwright; starts both servers itself):

```bash
cd src/secopent/interfaces/web && npx playwright install chromium && npx playwright test
```

## License

Apache-2.0. See [LICENSE](LICENSE).
