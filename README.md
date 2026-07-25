# SecOpent

Catalog-driven Agent-native authorized pentest workbench.

> Status: **M3 complete** (model-driven logic testing). M0 foundation + deterministic spine ✅; M1 knowledge layer + four-domain adapter pack ✅; M2 verification + case engine ✅; M3 AppModel (build/sign) + five-class logic test generator (skip/out-of-order/replay/boundary/invariant) with idempotent signatures + ModelBuilder (OpenAPI/Postman/traffic import) + DriftDetector + versioned ModelRegistry + model-generated fast path ✅. Next: M4 (agent interface + orchestration + report + web).
> Design: see `sepcs/2026-07-25-catalog-driven-agent-workbench-design.md`.

## Milestones

- **M0** — foundation + deterministic spine (projects/scope/assessment/audit, PolicyEngine, SQLite WAL, Repository contract)
- **M1** — knowledge layer + adapter pack (TestCatalog, CoverageMatrix, Intel + provenance, signed update bundles, health monitor, 17 adapters across asset/web/network/cloud, coverage gate)
- **M2** — verification + case engine (oracle N/N via pentest-ai, VerificationMethodRegistry, canary tokens, self-hosted Interactsh OOB, ground-truth range regression, YAML case DSL with no-eval AST interpreter, static risk gate, case lifecycle, fixture runner, seccomp Python sandbox, three-layer evidence + redaction)
- **M3** — model-driven logic testing (signed AppModel state machine/invariants/fields/roles, OpenAPI/Postman/traffic import + human validation + Ed25519 signing, five-class logic test generator with idempotent signatures, drift detection, versioned ModelRegistry with per-assessment snapshots, model-generated case fast path)
- **M4** — agent interface + orchestration + report + web *(next)*
- **M5** — security hardening + Beta

## Docs

- [Core boundaries (M0)](docs/architecture/core-boundaries.md)
- [Knowledge layer](docs/architecture/knowledge-layer.md)
- [Adapter pack (four domains)](docs/adapters/README.md)
- [Verification / oracle](docs/architecture/verification.md)
- [YAML case DSL](docs/cases/yaml-dsl.md)
- [Model-driven logic](docs/architecture/model-driven-logic.md)
- [AppModel schema](docs/appmodel/schema.md)

## Quickstart

```bash
py -3.12 -m pip install -e ".[dev]"
py -3.12 -m pytest -q
```

## License

Apache-2.0. See [LICENSE](LICENSE).
