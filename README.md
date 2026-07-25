# SecOpent

Catalog-driven Agent-native authorized pentest workbench.

> Status: **M4 complete** (agent interface + orchestration + report). M0 foundation + deterministic spine ✅; M1 knowledge layer + four-domain adapter pack ✅; M2 verification + case engine ✅; M3 model-driven logic testing ✅; M4 AssetGraph + finding correlation (deterministic fingerprint) + Planner DAG + Orchestrator (leased jobs) + data-driven ReportRenderer + MCP tool registry (trust levels) + FastAPI API + CLI + persistence + end-to-end assessment integration ✅. Next: M5 (security hardening + Beta).
> Design: see `sepcs/2026-07-25-catalog-driven-agent-workbench-design.md`.

## Milestones

- **M0** — foundation + deterministic spine (projects/scope/assessment/audit, PolicyEngine, SQLite WAL, Repository contract)
- **M1** — knowledge layer + adapter pack (TestCatalog, CoverageMatrix, Intel + provenance, signed update bundles, health monitor, 17 adapters across asset/web/network/cloud, coverage gate)
- **M2** — verification + case engine (oracle N/N via pentest-ai, VerificationMethodRegistry, canary tokens, self-hosted Interactsh OOB, ground-truth range regression, YAML case DSL with no-eval AST interpreter, static risk gate, case lifecycle, fixture runner, seccomp Python sandbox, three-layer evidence + redaction)
- **M3** — model-driven logic testing (signed AppModel state machine/invariants/fields/roles, OpenAPI/Postman/traffic import + human validation + Ed25519 signing, five-class logic test generator with idempotent signatures, drift detection, versioned ModelRegistry with per-assessment snapshots, model-generated case fast path)
- **M4** — agent interface + orchestration + report (AssetGraph relation table, deterministic finding fingerprint de-dup, Planner DAG from catalog+AppModel, single-machine Orchestrator with DB job lease + retry/deny classification, data-driven ReportRenderer with redaction + completeness gate, MCP tool registry with trust levels, FastAPI command/query API with idempotency + SSE, argparse CLI, asset/finding/report/job persistence, end-to-end assessment integration)
- **M5** — security hardening + Beta *(next)*

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

## Quickstart

```bash
py -3.12 -m pip install -e ".[dev]"
py -3.12 -m pytest -q
```

## License

Apache-2.0. See [LICENSE](LICENSE).
