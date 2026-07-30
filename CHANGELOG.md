# Changelog

All notable changes to SecOpent are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The version single source of truth is `src/secopent/__version__.py`; `scripts/release.sh`
stamps it and tags the matching `v<version>`.

## [Unreleased]

The v1.1-stable release: real end-to-end orchestration across all four execution
domains, hardened CI, ops-grade backup/restore, and a single-source release process.
(Run `scripts/release.sh 1.1.0-stable` to date and tag this section.)

### Added
- §3.2 end-to-end orchestration: `AdapterStepRunner` glue drives the Planner's
  `PlanStep` through the `Orchestrator` to real digest-pinned tool containers
  (Web nuclei/Juice Shop, API nuclei/httpbin, cloud checkov IaC).
- Cloud/container parsers wired into `RealScanRunner` (trivy/prowler/kube_bench/
  checkov/scoutsuite) + schemathesis, completing four-domain coverage.
- CI hardening: full-package strict mypy (218+ files), frontend build job,
  Playwright browser-e2e job, real-orchestration e2e job, coverage gate 80%.
- Backup/restore: `secopent restore` (audit-chain-verified, atomic, rollback
  point), `backup --include-secrets` (encrypted store; Fernet master key never
  in backup), `scripts/verify_backup.py`, and `docs/ops/backup-restore.md`.
- Release process: version single source (`__version__.py` + pyproject dynamic),
  this CHANGELOG, `scripts/release.sh`, and `.github/release.yml`.

### Fixed
- Adapter tool output is decoded as UTF-8 (was the locale codec, e.g. gbk on
  zh-CN Windows, which lost non-ASCII tool output).
- checkov parser flattens the multi-framework JSON array emitted by checkov ≥3.x.
- Adapter containers map `host.docker.internal:host-gateway` so they reach
  host-mapped targets on Linux CI (harmless on Docker Desktop).

## [1.1.0-web] - 2026-07-28

### Added
- Web Case Studio: 7 pages + AppModel editor (React + @xyflow/react DAG).
- LLM propose-only boundary enforced (actor_role on approvals/verdict/signing).
- Production hardening: key rotation, audit HMAC, structured logging, backup.
- Intel knowledge layer: OSV sync CLI, real health checkers, signed update bundle.
- Performance: SQLite WAL tuning, SSE backpressure, DAG viewport virtualization,
  adapter `--parallel N` with a race-free job lease.

### Fixed
- LLM boundary: `agent` actor is denied (403) on human-only actions
  (sign/publish/approve/verdict/stop/signing-key-create).

## [1.0.0-p0] - 2026-07-27

### Added
- Domain + policy baseline: scope/policy engine, 10-step authorization chain,
  Deny-precedence and Destructive-never rules.
- Verification: deterministic oracle, rescan verifier, evidence three-tier model.
- Adapter contract plane (manifests, digest-pinned upstream, four domains).
- Audit hash chain (signed) with rotation + GDPR redaction.
