# W3-E: Canary OOB 接线 -- Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans.

**Goal:** 把 OOB canary 验证（SSRF/XXE/反序列化）接线进 oracle。当前 `InteractshClient` + `canary.oob_subdomain` 已建，但 `RescanVerifier` 只做 echo/legacy 子串匹配--OOB vuln 类型从不走回调校验。

**Architecture:** `RescanVerifier` 增加可选 `interactsh: InteractshClient | None` + `oob_sleep`。`reproduce()` 中：若 `method.oob_window_seconds > 0` 且 interactsh 且 scan_kwargs 含 `{{canary_oob_subdomain}}` 占位 -> OOB 路径（`allocate_correlated` 拿 `(subdomain, correlation_domain)`，嵌入占位，scan，sleep `oob_window_seconds`，`has_callback` -> SUCCESS/FAILURE）。否则回落现有 echo/legacy 路径。`InteractshClient.allocate_correlated(token) -> (subdomain, correlation_domain)`（非破坏性，补充 `allocate` 的 API 缺口）。`RescanVerifierFactory` 透传 interactsh。composition root 用 `NullInteractshTransport`（无服务器时 OOB 静默 FAIL；真实 transport 是 M5）。

**Tech Stack:** Python 3.12、`py -3.12 -m pytest`、ruff/mypy/bandit -ll、coverage ≥80%。

## 现状
- `infrastructure/oracle/interactsh.py::InteractshClient`：`allocate(token) -> str`（full subdomain），`has_callback(token, correlation_domain)`（需 bare domain）--API 缺口：allocate 不返回 correlation domain。
- `canary.oob_subdomain(token) -> <token>.oast.example.com`（固定域，未接 oracle）。
- `RescanVerifier`：echo（`{{canary_token}}` 占位）或 legacy 子串。无 OOB。
- `VerificationMethod.oob_window_seconds`：0=非 OOB；SSRF/XXE/反序列化 >0。
- `tests/infrastructure/test_interactsh.py`：覆盖 allocate/collect/has_callback。

## File Structure
- 改 `infrastructure/oracle/interactsh.py` -- `allocate_correlated` 方法
- 改 `infrastructure/oracle/rescan_verifier.py` -- OOB 路径 + interactsh 注入
- 改 `infrastructure/oracle/verifier_factory.py` -- 透传 interactsh
- 新增 `infrastructure/oracle/null_interactsh.py` -- `NullInteractshTransport`
- 改 `interfaces/api/main.py` -- composition root 装 InteractshClient
- 新增 `tests/infrastructure/test_rescan_verifier_oob.py`
- 改 `tests/infrastructure/test_interactsh.py` -- allocate_correlated 覆盖

## Tasks

### T1: InteractshClient.allocate_correlated
新方法 `allocate_correlated(canary_token) -> tuple[str, str]`（subdomain, correlation_domain）。非破坏性（保留 `allocate`）。测试：返回 `(f"{token}.oast.example.com", "oast.example.com")` + has_callback 用返回的 correlation_domain 工作。

### T2: RescanVerifier OOB 路径
加 `interactsh: InteractshClient | None = None` + `oob_sleep: Callable[[float], None] = time.sleep`。`reproduce()`：OOB 分支（`method.oob_window_seconds > 0` and interactsh and `{{canary_oob_subdomain}}` in kwargs）-> allocate_correlated, embed, scan, oob_sleep(window), has_callback -> SUCCESS/FAILURE。新增 `OOB_PLACEHOLDER = "{{canary_oob_subdomain}}"`。测试：fake transport（有/无回调）+ fake runner + sleep=noop。

### T3: RescanVerifierFactory 透传 interactsh
`__init__(scan_runner, template_host_dir, canary, *, interactsh=None)`。`for_finding` 构造 `RescanVerifier(..., interactsh=self._interactsh)`。

### T4: NullInteractshTransport + composition root
`NullInteractshTransport`：register 返回 `"oast.null"`，poll 返回 `[]`。composition root：`InteractshClient(NullInteractshTransport())` -> factory。测试：app.state.oracle 的 factory 有 interactsh。

### T5: E2E + 质量门禁 + 文档
E2E：OOB vuln 类型（SSRF）+ fake transport 有回调 -> CONFIRMED；无回调 -> 不 CONFIRMED。全量门禁。docs：verification.md OOB 接线段 + 已知局限（无服务器时 OOB 静默 FAIL，M5 接真实 transport）。

## Self-Review
- **非破坏性**：`allocate` 保留；OOB 路径 gated by placeholder + window>0 + interactsh。✓
- **可测试**：sleep 注入；fake transport。✓
- **DDD 边界**：RescanVerifier/InteractshClient 都在 infrastructure；OracleService 不变（仍通过 factory）。✓
- **已知局限**：NullInteractshTransport -> OOB 永远 FAIL（无回调）；真实 OOB 需 M5 interactsh-server + `SECOPTENT_INTERACTSH_SERVER_URL`。OOB sleep 阻塞 oracle 线程（N×window）。
