# W4 Release-Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close the three remaining "已建未接线" gaps (peer-agents, netns, OOB canary) + the schema-management gap + a cleanup sweep, so SecOpent is v1.0-release-ready.

**Architecture:** Five workstreams, each independently shippable. W4-A (peer-agent) is the largest: construct `PeerAgentService` in `create_app` behind a feature flag + add a `peer_agents` router with a `NullPeerAgentHarness` fallback. W4-B makes `NetnsIsolator` real per-assessment (factory + lifecycle). W4-C makes the OOB canary path ACTIVE (real `HttpInteractshTransport` + placeholders in `scan_kwargs`). W4-D makes alembic the production schema source of truth. W4-E sweeps stale docs/dead code.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2.0, alembic, pytest, ruff/mypy/bandit. Tests run via `py -3.12 -m pytest -q`.

---

## Pre-conditions (done, do not redo)

- W2-A..W3-F complete (auth chain, oracle, audit persistence, domain state machines, canary OOB scaffolding, netns primitives all merged).
- Test suite green: 1261 passed, 5 skipped (86s).
- C1 credential leak: local + remote history scrubbed (force-pushed 2026-08-04).

## File Map (created / modified per workstream)

**W4-A (peer-agent wiring):**
- CREATE `src/secopent/infrastructure/peer_agents/null_harness.py` - `NullPeerAgentHarness` for graceful degradation.
- MODIFY `src/secopent/infrastructure/peer_agents/in_memory_peer_runs.py` - add `list()` method.
- MODIFY `src/secopent/application/ports/peer_runs.py` - add `list()` to `PeerRunRepository` Protocol.
- CREATE `src/secopent/interfaces/api/routers/peer_agents.py` - 5 routes.
- MODIFY `src/secopent/interfaces/api/routers/__init__.py` - export `peer_agents_router`.
- MODIFY `src/secopent/interfaces/api/main.py` - feature flag + construct service + register router + propagate to `/api`.
- CREATE `tests/e2e_real/test_peer_agent_wiring.py` - contract-level wiring E2E.

**W4-B (netns lifecycle):**
- MODIFY `src/secopent/interfaces/api/main.py` - construct `NetnsIsolator` + enforcer factory closure on `app.state`.
- MODIFY `src/secopent/interfaces/api/routers/assessments.py` - per-assessment netns create/destroy in `_run()`.
- MODIFY `tests/infrastructure/test_netns_isolator.py` (or new `test_assessment_netns_lifecycle.py`) - lifecycle test.

**W4-C (OOB canary active):**
- CREATE `src/secopent/infrastructure/oracle/http_interactsh.py` - `HttpInteractshTransport`.
- MODIFY `src/secopent/infrastructure/oracle/verifier_factory.py` - embed `{{canary_token}}` + `{{canary_oob_subdomain}}` in `scan_kwargs`.
- MODIFY `src/secopent/interfaces/api/main.py` - transport selection on `SECOPTENT_INTERACTSH_SERVER_URL`.
- CREATE `tests/infrastructure/test_http_interactsh.py` + extend E2E.

**W4-D (alembic as source of truth):**
- MODIFY `src/secopent/infrastructure/db/session.py` - `init_db` mode param + `SECOPTENT_DB_INIT` env.
- MODIFY `src/secopent/infrastructure/db/engine.py` (or CLI module) - `secopent db upgrade` / `secopent db stamp` commands.
- CREATE `tests/infrastructure/test_db_init_modes.py` + `test_alembic_schema_equivalence.py`.

**W4-E (cleanup):**
- MODIFY `src/secopent/infrastructure/safety/emergency_infra.py` - fix `NullPermitRevoker` docstring.
- MODIFY `src/secopent/interfaces/api/routers/assessments.py` - remove unreachable `EmergencyStop` fallback branch.
- MODIFY `src/secopent/interfaces/web/src/features/case-studio/DriftView.tsx` - wire to `POST /drift` OR remove tab.
- DELETE `src/secopent/interfaces/web/src/.../PagePlaceholder.tsx` (dead code).
- MODIFY `src/secopent/integrations/adapters/subfinder/__init__.py` - document/pin digest.

---

## W4-A: Peer-Agent Wiring (8 tasks)

**Context:** `infrastructure/peer_agents/` (8 files: strix/shannon/harness/composition) is fully built but `main.py` never calls `create_peer_agent_service()`, no router exists, frontend has no peer UI. `create_peer_agent_service` (composition.py:75-121) needs: `audit: AuditService`, `runs: PeerRunRepository`, `llm_provider: str`, `secret_lookup: Mapping[str,str]` (must contain `"LLM_API_KEY"`), `workdir_root: Path`, optional `enable_shannon`. Docker socket required for real harness; no Null harness exists. Images unpinned (strix=`""`, shannon=`""`) so E2E stays contract-level. Peer-agent is a separate operator-triggered flow (NOT inline in `execute_assessment`); outcome feeds `propose_replan_from_outcome` for human approval.

### W4-A T1: NullPeerAgentHarness (graceful degradation)

**Why:** Mirror the LLM `NullModelBackend` pattern - when Docker/images unavailable, `launch()` returns an empty `PeerRunOutcome` instead of crashing. Lets the router degrade to 503 or empty-result cleanly.

1. Write failing test `tests/infrastructure/test_null_peer_harness.py`:
   ```python
   from secopent.infrastructure.peer_agents.null_harness import NullPeerAgentHarness
   from secopent.domain.peer_agents.models import PeerAgentReport  # adjust import

   def test_null_harness_launch_returns_empty_report() -> None:
       h = NullPeerAgentHarness()
       report = h.launch(agent_name="strix", targets=("10.0.0.1",), run_id="r1", secret_lookup={})
       assert report.observations == ()
       assert report.rejected == ()
   ```
2. Run `py -3.12 -m pytest tests/infrastructure/test_null_peer_harness.py -q` -> RED (import fails).
3. Create `src/secopent/infrastructure/peer_agents/null_harness.py`:
   ```python
   """NullPeerAgentHarness: no-op harness for graceful degradation (W4-A T1).

   Returned by the composition root when Docker/images are unavailable so the
   PeerAgentService degrades to empty outcomes instead of failing at launch.
   """
   from __future__ import annotations
   from collections.abc import Mapping
   from secopent.domain.peer_agents.models import PeerAgentReport

   class NullPeerAgentHarness:
       def launch(self, *, agent_name, targets, run_id, secret_lookup) -> PeerAgentReport:
           return PeerAgentReport(observations=(), rejected=())
       def terminate(self, run_id: str) -> None: ...
   ```
   (Match the exact `PeerAgentHarness` Protocol signature from `application/peer_agents.py:46-53`.)
4. Run test -> GREEN.
5. `ruff check src/secopent/infrastructure/peer_agents/null_harness.py tests/infrastructure/test_null_peer_harness.py --fix` + `mypy`.
6. Commit: `feat(peer-agents): NullPeerAgentHarness for graceful degradation (W4-A T1)`.

### W4-A T2: PeerRunRepository.list() extension

**Why:** `GET /assessments/{id}/peer-runs` needs to list runs; the Protocol (`ports/peer_runs.py` / `ports/repositories.py:122-124`) only has `get`/`add`/`save`.

1. Write failing test `tests/infrastructure/test_in_memory_peer_runs.py`:
   ```python
   def test_list_for_assessment_returns_added_runs() -> None:
       repo = InMemoryPeerRunRepository()
       repo.add(run_for("a1"))  # helper builds a PeerRun with assessment_id="a1"
       assert len(repo.list_for_assessment("a1")) == 1
       assert repo.list_for_assessment("other") == []
   ```
2. Run -> RED.
3. Add `list_for_assessment(self, assessment_id: str) -> tuple[PeerRun, ...]` to the `PeerRunRepository` Protocol (in `ports/`) and implement in `InMemoryPeerRunRepository` (filter internal dict by `assessment_id`).
4. Run -> GREEN. `ruff` + `mypy`.
5. Commit: `feat(peer-agents): PeerRunRepository.list_for_assessment (W4-A T2)`.

### W4-A T3: peer_agents router (5 routes)

1. Write failing test `tests/interfaces/api/test_peer_agents_router.py` covering each route with an injected fake `PeerAgentService` on `app.state.peer_agent_service`:
   - `POST /assessments/{aid}/peer-runs` -> 200, `PeerRunOutcome` shape.
   - `GET /assessments/{aid}/peer-runs` -> 200, list.
   - `GET /peer-runs/{run_id}` -> 200 or 404.
   - `POST /peer-runs/{run_id}/stop` -> 200.
   - `GET /peer-agents` -> 200, list of agent descriptors.
   - When `app.state.peer_agent_service is None` -> 503 on all routes.
2. Run -> RED.
3. Create `src/secopent/interfaces/api/routers/peer_agents.py` with an `APIRouter()` and the 5 routes. Each route reads `service = getattr(request.app.state, "peer_agent_service", None)`; if None -> `raise HTTPException(503, "peer agents disabled")`. Call the corresponding `PeerAgentService` method (`launch`, `list_for_assessment`, `get`, `stop`, `registry.all()`). Define Pydantic request/response models matching `domain/peer_agents/models.py`.
4. Run -> GREEN. `ruff` + `mypy`.
5. Commit: `feat(peer-agents): peer_agents router with 5 routes (W4-A T3)`.

### W4-A T4: router registration + /api propagation

1. Failing assertion in `test_peer_agents_router.py` (or a new `test_app_registration.py`): `create_app()` includes the peer_agents router on both root and `/api`.
2. Run -> RED.
3. MODIFY `routers/__init__.py`: add `from .peer_agents import router as peer_agents_router` + add `"peer_agents_router"` to `__all__`.
4. MODIFY `main.py` `_register_api` (~line 228-247): `api.include_router(peer_agents_router, prefix="")` alongside the others.
5. Run -> GREEN.
6. Commit: `feat(peer-agents): register peer_agents router on root + /api (W4-A T4)`.

### W4-A T5: composition root wiring (feature flag + construct + audit service)

1. Failing test: `create_app()` with `SECOPTENT_PEER_AGENTS_ENABLED=1` + `LLM_API_KEY` set -> `app.state.peer_agent_service is not None` and `isinstance(..., PeerAgentService)`; without the flag -> `app.state.peer_agent_service is None`.
2. Run -> RED.
3. MODIFY `main.py` after the LLM gateway block (~line 443). Build inputs:
   - `audit_service = AuditService(SqlAlchemyAuditRepository(...))` (mirror `execution.py:279`).
   - `runs = InMemoryPeerRunRepository()`.
   - `llm_provider = os.environ.get("SECOPTENT_PEER_LLM", "openai/gpt-4o-mini")`.
   - `secret_lookup = {"LLM_API_KEY": os.environ.get("LLM_API_KEY", "")}`.
   - `workdir_root = Path(os.environ.get("SECOPTENT_PEER_WORKDIR", "./peer_work"))`.
   - Harness: `NullPeerAgentHarness()` (images unpinned for now; real `ContainerPeerAgentHarness` deferred until digests pinned - leave a TODO comment referencing W4-A follow-up).
   ```python
   if os.environ.get("SECOPTENT_PEER_AGENTS_ENABLED") == "1":
       app.state.peer_agent_service = create_peer_agent_service(
           audit=audit_service, runs=runs, llm_provider=llm_provider,
           secret_lookup=secret_lookup, workdir_root=workdir_root,
           harness=NullPeerAgentHarness(),  # real harness when image digests pinned
       )
   else:
       app.state.peer_agent_service = None
   ```
   (If `create_peer_agent_service` doesn't accept a `harness=` kwarg, add one with default `None` -> uses `ContainerPeerAgentHarness` when None; pass `NullPeerAgentHarness()` explicitly here.)
4. Propagate to `/api` sub-app (~line 451-465): `api.state.peer_agent_service = app.state.peer_agent_service`.
5. Run -> GREEN. `ruff` + `mypy` + `bandit -ll`.
6. Commit: `feat(peer-agents): wire PeerAgentService in create_app behind feature flag (W4-A T5)`.

### W4-A T6: wiring E2E (contract-level)

1. Failing E2E `tests/e2e_real/test_peer_agent_wiring.py` (not marked `peer_real` - runs in CI):
   - `create_app()` with flag set -> `app.state.peer_agent_service` not None.
   - Flag unset -> None + `GET /peer-agents` returns 503.
   - With flag set + fake harness injected -> `GET /peer-agents` returns 200 with strix descriptor; `POST /assessments/{id}/peer-runs` returns 200 with empty `PeerRunOutcome` (Null harness).
2. Run -> RED.
3. Implement by injecting a fake service onto `app.state` in the test (don't go through real Docker). Use FastAPI `TestClient`.
4. Run -> GREEN.
5. Commit: `test(peer-agents): contract-level wiring E2E (W4-A T6)`.

### W4-A T7: docs

1. MODIFY `docs/deployment.md` §8 checklist: add `- [ ] Peer-agent 接线（W4-A）：`SECOPTENT_PEER_AGENTS_ENABLED=1` + `LLM_API_KEY` 启用；镜像未 pin digest，当前用 NullPeerAgentHarness 降级；真 strix/shannon 容器待镜像构建后接入`.
2. Commit: `docs(deployment): W4-A peer-agent wiring note (W4-A T7)`.

### W4-A T8: quality gate

1. `py -3.12 -m pytest -q` (full suite green).
2. `ruff check src tests --fix` + `mypy src` + `bandit -ll -r src`.
3. `py -3.12 -m pytest --cov=src --cov-report=term-missing` -> coverage still >= 80%.
4. Commit if any fixups: `chore: W4-A quality gate fixups`.

---

## W4-B: Netns Composition-Root + Per-Assessment Lifecycle (4 tasks)

**Context:** `NetnsIsolator` (W3-F T1) + `NftScopeEnforcer(netns=)` (W3-F T2) are built but `main.py` never constructs the isolator and constructs the enforcer WITHOUT `netns=`, so nft rules run in the host default netns. The enforcer is currently a singleton on `app.state.nft_scope_enforcer` (read at `assessments.py:271`). Per-assessment isolation requires per-assessment netns -> per-assessment enforcer construction.

### W4-B T1: NetnsIsolator + enforcer factory in composition root

1. Failing test: `create_app()` exposes `app.state.netns_isolator` (a `NetnsIsolator`) and `app.state.make_nft_enforcer` (a callable taking `netns: str | None` -> `NftScopeEnforcer`). Calling `make_nft_enforcer("foo")` returns an enforcer whose `_netns == "foo"`; `make_nft_enforcer(None)` returns one with `_netns is None`.
2. Run -> RED.
3. MODIFY `main.py`: construct `netns_isolator = NetnsIsolator()` -> `app.state.netns_isolator`. Replace the current singleton `NftScopeEnforcer(...)` construction with a factory closure:
   ```python
   _shared_dns = SocketDnsResolver()
   _shared_guard = EgressGuard(_shared_dns)
   def make_nft_enforcer(netns: str | None) -> NftScopeEnforcer:
       return NftScopeEnforcer(_shared_dns, guard=_shared_guard, audit=audit_sink, netns=netns)
   app.state.make_nft_enforcer = make_nft_enforcer
   app.state.nft_scope_enforcer = make_nft_enforcer(None)  # backward-compat for non-Linux
   ```
4. Run -> GREEN. `ruff` + `mypy`.
5. Commit: `feat(egress): NetnsIsolator + NftScopeEnforcer factory in composition root (W4-B T1)`.

### W4-B T2: per-assessment netns lifecycle in start_assessment

1. Failing test `tests/interfaces/api/test_assessment_netns_lifecycle.py`: on a Linux-faking app (monkeypatch `NetnsIsolator.is_supported` -> True + recording runner), `start_assessment` -> `_run()` creates a netns named `secopent-<assessment_id>`, passes an enforcer with that netns to `execute_assessment`, and destroys the netns in `finally`. On `is_supported()` False (Windows dev), no netns created, enforcer gets `netns=None`.
2. Run -> RED.
3. MODIFY `assessments.py` `_run()` (inside `start_assessment`, ~line 274): replace `nft_scope_enforcer = getattr(request.app.state, "nft_scope_enforcer", None)` with:
   ```python
   isolator = getattr(request.app.state, "netns_isolator", None)
   make_enforcer = getattr(request.app.state, "make_nft_enforcer", None)
   netns_handle = None
   if isolator is not None and isolator.is_supported() and make_enforcer is not None:
       netns_handle = isolator.create(assessment_id)
       nft_scope_enforcer = make_enforcer(netns_handle.name)
   elif make_enforcer is not None:
       nft_scope_enforcer = make_enforcer(None)
   else:
       nft_scope_enforcer = getattr(request.app.state, "nft_scope_enforcer", None)
   ```
   Wrap the `execute_assessment(...)` call in `try/finally` and in `finally`: `if netns_handle is not None: isolator.destroy(netns_handle)` (best-effort, log+audit on failure).
4. Run -> GREEN. `ruff` + `mypy`.
5. Commit: `feat(egress): per-assessment netns lifecycle in start_assessment (W4-B T2)`.

### W4-B T3: lifecycle test + non-Linux no-op

1. Extend T2's test file: assert on non-Linux (`is_supported()` False) no `ip netns add` is issued (recording runner empty) and `execute_assessment` still runs with `netns=None` enforcer. Assert cleanup destroys netns even when `execute_assessment` raises.
2. Run -> GREEN (should already pass after T2; add the raise-path assertion).
3. Commit: `test(egress): netns lifecycle cleanup-on-failure + non-Linux no-op (W4-B T3)`.

### W4-B T4: docs + quality gate

1. MODIFY `docs/deployment.md` §8 W3-F bullet: update to note `NetnsIsolator` is now wired in `create_app` + per-assessment lifecycle in `start_assessment`; remaining Docker-`--network`-into-netns still Linux-only.
2. Full suite + ruff + mypy + bandit + coverage.
3. Commit: `docs(deployment): W4-B netns lifecycle wired (W4-B T4)`.

---

## W4-C: OOB Canary Active (5 tasks)

**Context:** OOB path is doubly inert. (a) `main.py:418` always `NullInteractshTransport`. (b) `verifier_factory.py:41` `args` has no `{{canary_oob_subdomain}}` / `{{canary_token}}` placeholder, so `RescanVerifier.reproduce` OOB branch (`rescan_verifier.py:100`) and echo branch (`:112`) never fire. Both placeholders are substring-matched anywhere in `scan_kwargs` (dict/list/tuple recursion via `_contains`/`_replace`, `rescan_verifier.py:41-61`). interactsh-server is self-hostable (image catalogued `image_catalog.py:58`, docker-compose at `scripts/provision/docker-compose.interactsh.yml`).

### W4-C T1: HttpInteractshTransport

1. Failing test `tests/infrastructure/test_http_interactsh.py`: against a stub HTTP server (use `http.server` in a thread or `responses`/`pytest-httpserver`), `HttpInteractshTransport(server_url).register()` returns a correlation domain; `.poll(correlation)` returns parsed interaction records. Assert 404/non-200 raises.
2. Run -> RED.
3. CREATE `src/secopent/infrastructure/oracle/http_interactsh.py`:
   ```python
   """HttpInteractshTransport: real InteractshTransport over a self-hosted interactsh-server (W4-C T1)."""
   from __future__ import annotations
   import urllib.request, json
   from .interactsh import InteractshTransport

   class HttpInteractshTransport(InteractshTransport):
       def __init__(self, server_url: str, *, timeout: float = 10.0) -> None:
           self._url = server_url.rstrip("/"); self._timeout = timeout
       def register(self) -> str:
           # POST {server_url}/register -> {"domain": "...", "correlation_id": "..."}
           ...  # return correlation domain
       def poll(self, correlation_domain: str) -> list[dict]:
           # GET {server_url}/poll?id={correlation} -> list of interaction records
           ...
   ```
   (Match the exact `InteractshTransport` Protocol from `interactsh.py:30-39` - `register() -> str` returns the correlation domain, `poll(correlation_domain) -> list[dict]`.)
4. Run -> GREEN. `ruff` + `mypy` + `bandit -ll` (network call - ensure no SSRF into blocked CIDRs; the server URL is operator-configured, not user input).
5. Commit: `feat(oracle): HttpInteractshTransport for self-hosted interactsh-server (W4-C T1)`.

### W4-C T2: embed canary placeholders in scan_kwargs

1. Failing test `tests/infrastructure/test_verifier_factory.py::test_scan_kwargs_carries_canary_placeholders`: `RescanVerifierFactory.for_finding(finding)` returns a `RescanVerifier` whose `_scan_kwargs` contains both `{{canary_token}}` and `{{canary_oob_subdomain}}` as substrings of some string in `args`.
2. Run -> RED.
3. MODIFY `verifier_factory.py:40-42` `for_finding`:
   ```python
   def for_finding(self, finding: Any) -> OracleVerifier:
       # Embed canary placeholders so RescanVerifier's echo + OOB branches can fire.
       # The canary token echoes back in scan output (echo path); the OOB subdomain
       # triggers a callback if the target renders the URL (OOB path). Both are
       # substring-replaced at reproduce time.
       asset_with_canary = f"{finding.asset}{'&' if '?' in finding.asset else '?'}cb={OOB_PLACEHOLDER}"
       args = ["-t", "/templates/", "-u", asset_with_canary, "-var", f"canary={CANARY_PLACEHOLDER}", "-jsonl", "-silent", "-duc"]
       scan_kwargs: dict[str, Any] = {"adapter_key": "nuclei", "args": args}
       ...
   ```
   Import `OOB_PLACEHOLDER` from `rescan_verifier` and `CANARY_PLACEHOLDER` from `canary.py`. (If `finding.asset` is not a URL with a query slot, append `#cb=...` instead - confirm with the test.)
4. Run -> GREEN. `ruff` + `mypy`.
5. Commit: `feat(oracle): embed canary placeholders in production scan_kwargs (W4-C T2)`.

### W4-C T3: transport selection in composition root

1. Failing test: `create_app()` with `SECOPTENT_INTERACTSH_SERVER_URL` set -> `app.state` oracle factory uses `HttpInteractshTransport`; without it -> `NullInteractshTransport` (current behavior).
2. Run -> RED.
3. MODIFY `main.py:415-421`:
   ```python
   interactsh_server_url = os.environ.get("SECOPTENT_INTERACTSH_SERVER_URL", "").strip() or None
   if interactsh_server_url:
       interactsh = InteractshClient(HttpInteractshTransport(interactsh_server_url))
   else:
       interactsh = InteractshClient(NullInteractshTransport())
   ```
   Import `HttpInteractshTransport`.
4. Run -> GREEN. `ruff` + `mypy` + `bandit -ll`.
5. Commit: `feat(oracle): select Http/Null InteractshTransport by env (W4-C T3)`.

### W4-C T4: E2E - OOB branch fires with real transport

1. Failing E2E `tests/e2e_real/test_oracle_oob_active.py`: with a stub interactsh server returning a callback for the correlation domain, a finding whose `VerificationMethod.oob_window_seconds > 0` verifies SUCCESS (callback seen) via the OOB branch. Assert the OOB branch is taken (not the legacy substring fallthrough) by checking the audit/return path.
2. Run -> RED.
3. Implement using `pytest-httpserver` or a threaded stub + `RealScanRunner` faked. Inject the stub transport into the factory.
4. Run -> GREEN.
5. Commit: `test(oracle): OOB canary branch fires end-to-end (W4-C T4)`.

### W4-C T5: docs + quality gate

1. MODIFY `docs/deployment.md` §8: add `- [ ] OOB canary 复证生效（W4-C）：`SECOPTENT_INTERACTSH_SERVER_URL` 指向自建 interactsh-server（见 scripts/provision/docker-compose.interactsh.yml）；未设则 OOB 降级为 Null（复证回退子串匹配）`.
2. MODIFY `docs/architecture/verification.md`: update W3-E paragraph to note placeholders now embedded in prod scan_kwargs + Http transport selectable.
3. Full suite + ruff + mypy + bandit + coverage.
4. Commit: `docs(verification): W4-C OOB canary active (W4-C T5)`.

---

## W4-D: Alembic as Production Schema Source of Truth (5 tasks)

**Context:** `session.py:44` `CoreBase.metadata.create_all(engine)` runs unconditionally in `init_db` (called at `Database.__init__`), so boot always creates tables from ORM metadata, bypassing alembic. `alembic/env.py` is correct (targets `CoreBase.metadata`, reads `SECOPTENT_DB_URL`). Baseline `ad674b51adca` exists. Policy: fresh DBs (no core tables) get `create_all` + `alembic stamp head` (dev/test convenience + tracked); existing DBs skip `create_all` and rely on operator-run `alembic upgrade head` (prod). Controlled by `SECOPTENT_DB_INIT` env: `auto` (default) / `always` (legacy, tests) / `skip` (prod).

### W4-D T1: init_db mode param + SECOPTENT_DB_INIT env

1. Failing test `tests/infrastructure/test_db_init_modes.py`:
   - `init_db(engine, mode="always")` on a non-empty DB -> idempotent (current behavior).
   - `init_db(engine, mode="skip")` -> does NOT create tables (assert no `core_projects` table).
   - `init_db(engine, mode="auto")` on fresh engine -> creates tables; on an engine with existing `core_projects` -> does NOT re-run create_all (assert no-op via inspecting call count or idempotence).
2. Run -> RED.
3. MODIFY `session.py:35-52` `init_db`:
   ```python
   def init_db(engine: Engine, *, mode: str | None = None) -> None:
       mode = mode or os.environ.get("SECOPTENT_DB_INIT", "auto")
       if mode == "skip":
           return
       if mode == "auto":
           from sqlalchemy import inspect
           if inspect(engine).has_table("core_projects"):
               return  # existing DB -> alembic owns schema; do not create_all
       # mode == "always" OR auto-fresh:
       CoreBase.metadata.create_all(engine)
       if engine.dialect.name == "sqlite":
           ...  # FTS5 DDL unchanged
   ```
   (`core_projects` is the canonical "is this DB initialized" sentinel - confirm the table name from `core_models.py`.)
4. Run -> GREEN. `ruff` + `mypy`.
5. Commit: `feat(db): init_db mode param + SECOPTENT_DB_INIT env (W4-D T1)`.

### W4-D T2: secopent db upgrade / stamp CLI

1. Failing test `tests/infrastructure/test_db_cli.py`: `secopent db upgrade --db sqlite:///:memory:` runs `alembic upgrade head` (assert tables created); `secopent db stamp --db <path>` stamps the current schema to head (assert `alembic_version` row exists).
2. Run -> RED.
3. Add `db` subcommand to the `secopent` CLI (find the CLI entry in `src/secopent/interfaces/cli/` or `__main__.py`):
   ```python
   # secopent db upgrade --db <url>: alembic upgrade head
   # secopent db stamp --db <url>: alembic stamp head (for existing create_all DBs)
   # secopent db current --db <url>: alembic current
   ```
   Use `alembic.config.Config` + `command.upgrade`/`command.stamp`. Set `SECOPTENT_DB_URL` env from `--db` so `alembic/env.py` picks it up.
4. Run -> GREEN. `ruff` + `mypy`.
5. Commit: `feat(db): secopent db upgrade/stamp/current CLI (W4-D T2)`.

### W4-D T3: stamp fresh DBs after create_all (auto mode tracks schema)

1. Failing test: after `init_db(engine, mode="auto")` on a fresh DB, `alembic_version` table exists with the baseline revision (so a subsequent `alembic upgrade` knows the starting point).
2. Run -> RED.
3. MODIFY `init_db` auto-fresh branch: after `create_all`, call `alembic.stamp head` (via `alembic.config.Config` + `command.stamp`) so the DB is tracked from baseline. Guard with try/except (best-effort - stamp failure shouldn't break boot; log a warning).
4. Run -> GREEN. `ruff` + `mypy`.
5. Commit: `feat(db): stamp fresh DBs to baseline after create_all (W4-D T3)`.

### W4-D T4: schema equivalence test (alembic baseline == create_all)

1. Failing test `tests/infrastructure/test_alembic_schema_equivalence.py`: build two engines on fresh SQLite DBs - one via `init_db(mode="always")` (create_all), one via `alembic upgrade head`. Compare table names + column sets (via `sqlalchemy.inspect`). Assert they match (ignoring `alembic_version` + `core_vulnerabilities_fts`).
2. Run -> if RED, the baseline migration is stale (new ORM tables added since baseline not in migration). Fix: regenerate the baseline migration (`alembic revision --autogenerate -m "sync baseline"`) OR add the missing tables to the baseline. Re-run -> GREEN.
3. Commit: `test(db): alembic baseline schema equivalence (W4-D T4)` (+ migration fix if needed).

### W4-D T5: docs + quality gate

1. MODIFY `docs/deployment.md` §4 (Database) + §8: document `SECOPTENT_DB_INIT` (auto/always/skip), `secopent db upgrade` as the prod pre-boot step, and that existing `create_all`-bootstrapped DBs should be `secopent db stamp`ed before first migration.
2. Full suite + ruff + mypy + bandit + coverage.
3. Commit: `docs(deployment): W4-D alembic source-of-truth policy (W4-D T5)`.

---

## W4-E: Cleanup Sweep (5 tasks)

### W4-E T1: fix stale NullPermitRevoker docstring + EmergencyStop fallback branch

1. MODIFY `src/secopent/infrastructure/safety/emergency_infra.py:11-13`: update docstring - permits ARE persisted in a revocable store (`InMemoryPermitRevoker` wired in `main.py:372`); `NullPermitRevoker` is now only the test/legacy fallback, not the production path.
2. MODIFY `assessments.py:353-360` `emergency_stop` route: remove the unreachable `if stop is None: stop = EmergencyStop(permit_revoker=NullPermitRevoker(), ...)` fallback (composition root is mandatory since W2-A). If `stop is None`, raise `HTTPException(503, "emergency stop not configured")` instead of silently revoking 0 permits.
3. Test: `test_emergency_stop_route_503_when_unconfigured` (create_app without composition root -> 503, not silent success).
4. Commit: `refactor(safety): fix stale NullPermitRevoker docstring + drop unreachable fallback (W4-E T1)`.

### W4-E T2: DriftView.tsx - wire to POST /drift or remove

1. Check `interfaces/web/src/features/case-studio/DriftView.tsx:6` - backend `POST /{app_id}/{version}/drift` exists (`appmodels.py:380`). Decision: if drift detection is a v1.0 feature, wire the frontend to call it; if not, remove the tab from the case-studio layout.
2. Implement the chosen option (wire = fetch + render drift results; remove = delete the tab + the component).
3. Build the frontend (`bash scripts/build_web.sh`) -> assert no type errors.
4. Commit: `feat(web): wire DriftView to /drift endpoint` OR `refactor(web): remove unbuilt DriftView tab (W4-E T2)`.

### W4-E T3: delete dead PagePlaceholder.tsx

1. Confirm `PagePlaceholder.tsx` has no importers (`grep -r "PagePlaceholder" interfaces/web/src/`). If none, delete the file.
2. `bash scripts/build_web.sh` -> green.
3. Commit: `refactor(web): delete dead PagePlaceholder component (W4-E T3)`.

### W4-E T4: subfinder digest - pin or document M5 ownership

1. `integrations/adapters/subfinder/__init__.py:24` has a placeholder digest. If the digest is known (from the M5 container build), pin it. If not, add a clear comment: `# digest pinned at M5 container build; tracked in <issue/ref>` and ensure the runtime digest-pinning check (image_catalog) is documented as a deployment gate.
2. Commit: `chore(adapters): document subfinder digest pinning ownership (W4-E T4)`.

### W4-E T5: quality gate (full sweep)

1. `py -3.12 -m pytest -q` + `ruff check src tests` + `mypy src` + `bandit -ll -r src` + coverage >= 80%.
2. Frontend build green (`bash scripts/build_web.sh`).
3. Commit any fixups: `chore: W4-E quality gate fixups`.

---

## Self-Review

1. **Spec coverage:** Every gap from the release-readiness assessment is covered - peer-agent (W4-A), netns (W4-B), OOB canary (W4-C), alembic (W4-D), cleanup items (W4-E). ✓
2. **Placeholder scan:** No TBD/TODO/vague steps. (W4-A T5 has one explicit TODO comment referencing image-digest follow-up - that's a code comment, not a plan placeholder.) ✓
3. **Type consistency:** `make_nft_enforcer(netns: str | None) -> NftScopeEnforcer`; `init_db(mode: str | None)`; `HttpInteractshTransport(server_url: str)` matches `InteractshTransport` Protocol. ✓
4. **Dependency order:** W4-A T1 (Null harness) before T5 (wiring uses it); W4-A T2 (list) before T3 (router uses it); W4-B T1 (factory) before T2 (lifecycle uses it); W4-C T1 (Http transport) before T3 (selection uses it); W4-D T1 (mode) before T3 (stamp uses mode). ✓

## Known deferrals (documented, not blocking v1.0)

- **Peer-agent real backends:** strix/shannon image digests unpinned; `NullPeerAgentHarness` wired until images built. Real-Docker E2E (`test_peer_strix_ab.py`) already exists for when images are ready.
- **Docker-container-into-netns:** W4-B wires `NetnsIsolator` + per-assessment netns for nft rules, but scan containers still run in the Docker default network. Full `--network` engineering to put the scan container INSIDE the netns is Linux-env-only (deferred from W3-F).
- **Interactsh server deployment:** W4-C makes the transport selectable + path active, but the operator must deploy interactsh-server (`scripts/provision/docker-compose.interactsh.yml`) and set `SECOPTENT_INTERACTSH_SERVER_URL`.
