# Changelog

All notable changes to SecOpent are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The version single source of truth is `src/secopent/__version__.py`; `scripts/release.sh`
stamps it and tags the matching `v<version>`.

## [0.1.2] - 2026-07-31

P0 blocker fix: the execution layer was not wired to the API. Approving an
assessment left it stuck at APPROVED with no path to trigger scans. This release
connects `POST /assessments/{id}/start` to the existing Orchestrator, closing
the core user journey (scope -> plan -> approve -> **execute** -> findings).

### Added
- `POST /assessments/{id}/start` endpoint: APPROVED -> QUEUED, spawns a daemon
  thread that runs `Orchestrator.dispatch` + `run_to_completion`, correlates
  observations into findings (tagged with `assessment_id`), and transitions
  RUNNING -> COMPLETED (or FAILED on exception). Human-only (agent -> 403).
- `AssessmentService.start/mark_running/complete/fail` state-transition methods
  with status guards (start only from APPROVED, etc.).
- `application/execution.py`: the API -> Orchestrator bridge (background
  executor, audit-recorded start/completed/failed).
- Frontend: `Start` button on AssessmentDetail (visible when APPROVED) + the
  `Emergency Stop` button is now enabled while RUNNING/QUEUED (was disabled
  with "lands with execution layer (P2)" placeholder).
- `useStartAssessment` / `useStopAssessment` hooks.

### Fixed
- Emergency stop works through container termination: `POST /stop` kills active
  adapter containers -> the step's subprocess fails -> `run_to_completion` raises
  -> the executor records FAILED. No separate stop-flag polling needed.
- User manual §3 step 5 updated to reflect the now-wired execution trigger
  (was aspirational "lands with execution layer (P2)").

### Notes
- SSE already polled `assessment.status`; it now emits the real QUEUED ->
  RUNNING -> COMPLETED transitions during execution. Per-step (job-level) SSE
  is a future enhancement (DAG nodes color at assessment granularity today).
- Findings are persisted after `run_to_completion` (not incrementally per step);
  incremental findings are a future enhancement.


## [0.1.1] - 2026-07-31

Linux deployment adaptation. No behavioral changes; the app is platform-agnostic
(Python code has no Windows paths/imports/platform branches, CI already runs on
ubuntu-latest). This release makes Linux first-class.

### Added
- Application `Dockerfile` (multi-stage: node builds the frontend, python:3.12-slim
  runs the app; installs docker CLI so the app can drive the host daemon via the
  mounted socket) + `.dockerignore`.
- `docs/deployment/linux.md`: Linux production deployment guide (venv + systemd
  service, containerized deployment with docker socket mount, nftables scoped
  egress, backup cron, journalctl logging, nginx reverse proxy, verification
  checklist).

### Changed
- `scripts/build_web.sh` and `scripts/verify_env.py`: replaced the Windows-only
  `py -3.12` launcher with `${PYTHON:-python3}` / `python3` (defaults to Linux;
  Windows users set `PYTHON=py` or use `py -3.12` per the README note).
- Docs (README, user-manual, environment-setup, adapter-guide): `py -3.12` ->
  `python3` throughout, with a one-line Windows note in README. Removed a
  hardcoded `F:\claudepc\SecOpent` path from environment-setup.

### Notes
- No file-permission changes were needed: `EncryptedFileBackend` and
  `Ed25519KeyProvider` keep secrets in memory (no on-disk secret file). The
  Linux deployment doc covers DB-file `chmod 600` at the ops layer.
- nftables scoped egress (T11) is runtime-usable on Linux for the first time
  (Windows could only unit-test it).


## [0.1.0] - 2026-07-31

First public release. Catalog-driven, agent-native **authorized** pentest
workbench: a deterministic spine (Planner, PolicyEngine, CoverageMatrix, oracle)
with an LLM that only ever *proposes* — humans and the deterministic layer
decide scope, approval, signing, findings, and publish.

### Added — Core platform
- Deterministic spine: projects / scope / assessment / audit hash chain,
  `PolicyEngine` 10-step authorization chain (Deny-precedence, Destructive-never,
  DNS-rebinding defense), `Repository` contract (SQLite WAL default, PostgreSQL
  swappable via `SECOPTENT_DB_URL`).
- Knowledge layer: versioned `TestCatalog` (OWASP WSTG + CIS baseline, seeded at
  startup), `CoverageMatrix` with coverage-regression gate, signed (Ed25519)
  update bundles with staging → atomic activate → rollback.
- 17 adapters across four domains (asset: subfinder/httpx/naabu/katana; web/API:
  nuclei/dalfox + Schemathesis; network: nmap; cloud: trivy/prowler/kube_bench/
  checkov/scoutsuite), each digest-pinned, non-root, cap-drop.
- Verification: deterministic oracle with `RescanVerifier` (real N/N rescan
  reproduction → CONFIRMED), three-tier evidence (RAW/REDACTED/SUMMARY), seccomp
  sandbox for YAML case DSL (no-eval interpreter).
- Model-driven logic testing: signed `AppModel` (state machine + invariants +
  field trust boundaries + roles), 5-class `LogicTestGenerator` (skip_step /
  out_of_order / replay via RESTler, boundary via Schemathesis, invariant
  violation self-built) with idempotent signatures + `DriftDetector`.
- Orchestration: `Planner` DAG → `Orchestrator` (job lease + retry) →
  `AdapterStepRunner` (PlanStep → real tool container → observations →
  `result_digest`); `ReportRenderer` with completeness gate.
- Agent interface: MCP tool registry, FastAPI (47 paths) + SSE, CLI, Web Case
  Studio (React + @xyflow/react DAG + Monaco YAML editor, 7 pages).
- Security hardening: `ScopeEnforcer`, signed `ExecutionPermit`, `SecretStore`
  (encrypted file backend, multi-key Ed25519 signing, rotation), signed
  `AuditChain` (HMAC, tamper-detectable), `EmergencyStop`, `PromptInjectionGuard`,
  `RemoteModelGateway` (MiniMax / OpenAI-compatible), STRIDE threat model.

### Added — v1.1 (this release)
- End-to-end orchestration proven across all four domains (real nuclei/dalfox/
  nmap/naabu/httpx/checkov against Juice Shop / httpbin / local Docker).
- CI hardening: full-package strict mypy, frontend build, Playwright browser-e2e,
  real-orchestration e2e, SAST (bandit/gitleaks/pip-audit/npm audit), coverage
  gate 80%.
- Backup/restore: `secopent restore` (audit-chain-verified, atomic), `backup
  --include-secrets`, `scripts/verify_backup.py`, ops runbook.
- Release process: version single-source, this CHANGELOG, `scripts/release.sh`.
- Performance: SQLite WAL tuning, SSE backpressure (bounded queue + disconnect
  cleanup + dedup), DAG viewport virtualization, adapter `--parallel N` with
  race-free job lease.
- Observability: structlog (request_id/tenant binding, redaction), Prometheus
  `/metrics` (5 metric families), OpenTelemetry tracing, Grafana dashboard.
- i18n: zh/en localization (react-i18next, default zh-CN; backend
  `Accept-Language` error localization).
- Database migrations: Alembic baseline + SQLite→PostgreSQL migration script.

### Fixed
- Adapter tool output decoded as UTF-8 (was locale codec, e.g. gbk on zh-CN
  Windows, losing non-ASCII output).
- checkov parser flattens the multi-framework JSON array emitted by checkov ≥3.x.
- Adapter containers map `host.docker.internal:host-gateway` for Linux CI
  reachability (harmless on Docker Desktop).
- LLM boundary: `agent` actor role is denied (403) on human-only actions
  (sign/publish/approve/verdict/stop/signing-key-create).

### Known limitations
- trivy cloud scan requires a reachable vulnerability DB (network-gated in some
  regions; checkov covers the cloud/container IaC domain offline).
- nftables scoped egress enforcement is implemented + unit-tested with a Linux
  CI job, but runtime verification requires a Linux host.
- Remote Worker execution (multi-machine) is designed (Tier 1 design ready) but
  not yet implemented — adapters run on the controller host in this release.

### Notes
This is the first *public* release. Internal development milestones (M0–M5,
Phase A, P0–P3) preceded it; their tags are not published. 0.1.0 reflects
semver initial-development semantics (0.x).
