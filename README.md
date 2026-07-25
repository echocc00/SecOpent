# SecOpent

Catalog-driven Agent-native authorized pentest workbench.

> Status: **M1 complete** (knowledge layer + four-domain adapter pack). M0 foundation + deterministic spine ✅; M1 TestCatalog / CoverageMatrix / Intel / Adapter contracts / four-domain Adapter Pack (17 adapters) / UpdateManager / HealthMonitor / CoverageService ✅. Next: M2 (verification + case engine).
> Design: see `sepcs/2026-07-25-catalog-driven-agent-workbench-design.md`.

## Milestones

- **M0** — foundation + deterministic spine (projects/scope/assessment/audit, PolicyEngine, SQLite WAL, Repository contract)
- **M1** — knowledge layer + adapter pack (TestCatalog, CoverageMatrix, Intel + provenance, signed update bundles, health monitor, 17 adapters across asset/web/network/cloud, coverage gate)
- **M2** — verification + case engine (oracle N/N, YAML case DSL, Python sandbox, risk gate) *(next)*
- **M3** — model-driven logic testing
- **M4** — agent interface + orchestration + report + web
- **M5** — security hardening + Beta

## Docs

- [Core boundaries (M0)](docs/architecture/core-boundaries.md)
- [Knowledge layer](docs/architecture/knowledge-layer.md)
- [Adapter pack (four domains)](docs/adapters/README.md)

## Quickstart

```bash
py -3.12 -m pip install -e ".[dev]"
py -3.12 -m pytest -q
```

## License

Apache-2.0. See [LICENSE](LICENSE).
