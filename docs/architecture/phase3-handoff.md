# Phase 3 详细设计与交接文档（功能缺口）

> 日期：2026-08-06（同日执行完毕）
> 状态：✅ 已执行并发布为 v0.5.0（提交链 37d3088..3c2ba78）
> 前置：v0.4.0 已发布（Phase 2 代码层完成）
> 路线图来源：`docs/architecture/handoff-roadmap.md` §Phase 3（本文件展开为可执行设计）

---

## 0. 总览

Phase 3 = 功能缺口：设计存在但未激活的能力。共 6 项，其中 **3.2 已由 P0-P3 + Phase 2.2 完成**，剩余 5 项约 **6-6.5 工作日**（3.6 经审阅扩大至含 API 端点，见 §0.5 E5）。

| # | 主题 | 优先级 | 工时 | 状态 | 依赖 |
|---|------|--------|------|------|------|
| 3.1 | Echo Canary Per-Method Gate | P2 | 1d | 待做（按 §0.5 E1/E2 修正执行） | 无 |
| 3.2 | Strix/Shannon 分层集成 | - | - | ✅ **已完成**（v0.4.0，P0-P3 + Phase 2.2） | - |
| 3.3 | DriftView 前端 UI | P3 | 1d | 待做（按 §0.5 E3） | 后端 `/drift` 已就绪 |
| 3.4 | LocalOllamaBackend | P3 | 1d | 待做（与 3.5 合并，按 §0.5 E4） | 与 3.5 合并为一项 |
| 3.5 | LLM Multi-Provider Config | P3 | 0.5d | 待做（与 3.4 合并，按 §0.5 E4） | 与 3.4 合并 |
| 3.6 | rotate/redact_pii + 审计链 API 端点 | P2 | 1-1.5d | 待做（范围扩大，见 §0.5 E5） | forbidden linter 已就绪 |

**推荐执行序**（按优先级 + 依赖）：
```
P2 先行：3.6 (0.5d, 安全相关) ──┐
         3.1 (1d, 验证完整性) ──┤
P3 随后：3.4+3.5 (1.5d, LLM 统一) ┤── 3.3 (1d, 前端) 独立并行
                                 └── 全部完成后发 v0.5.0
```

---

## 0.5 审阅勘误（2026-08-06，执行前必读）

设计稿经逐项源码复核，以下修正**优先于正文**；正文与勘误冲突时以勘误为准。

### E1（3.1，致命缺陷）：`echo_probe` 独立 key 方案作废

两条独立证据：
1. **会崩溃**：`RescanVerifier.reproduce` 用 `self._runner.scan(**kwargs)` 解包，而 `RealScanRunner.scan` 是严格签名（`adapter_key / args / mounts / source / resource_limits / capabilities`，无 `**kwargs`，`infrastructure/adapters/real_scan.py:131-140`）。scan_kwargs 多任何未知 key → `TypeError`。
2. **token 到不了靶标**：echo 验证要求 canary 出现在扫描 stdout（`rescan_verifier.py:123-126`）。不被 runner 消费的 dict key 永远不进入探测流量 → 真实反射型 XSS 的 N/N 复现全 FAILURE → 原本 legacy 可确认的发现变 REFUTED（与设计意图相反的回归）。

**修正方案**：echo canary 嵌入 `-u` URL 的查询参数（与 OOB 的 `cb={OOB_PLACEHOLDER}` 同机制）：
- factory 注入 `VerificationMethodRegistry`；`for_finding(finding)` 加 `vuln_type` 参数——`oracle_service._verify_one` 在 `oracle_service.py:79` 已算出 vuln_type、`:142` 才调 `for_finding`，现成可传。
- 仅当 `method.echo_enabled` 时 URL 追加 `&echo={{canary_token}}`；OOB placeholder 保持 always-on 现状。两分支互斥触发（OOB 门控 `oob_window_seconds>0`；echo-enabled 的 XSS `oob_window=0`），无占位符冲突。
- `rescan_verifier` 确实无需改（门控基于 placeholder 存在性）——正文此结论正确，但理由应改为本条。
- 连带：`OracleVerifierFactory` Protocol（`application/ports/oracle.py:18-21`）签名变更，所有测试 fake 同步改。

### E2（3.1，决策已确认）：严格 echo 语义

VulnType 枚举只有单一 `XSS`（`domain/verification/models.py:23-39`，无 XSS_REFLECTED/OPEN_REDIRECT/SSTI——正文"具体枚举值以现状为准"的 fallback 触发）。**用户确认采用严格语义**：XSS `echo_enabled=True`；无回显 → N/N FAILURE → REFUTED，无 legacy fallback。已知行为变更：不回显的 stored/DOM XSS 发现从弱 legacy 确认变为 REFUTED（重扫探针本就无法复现它们，属预期收紧）。正文 §1.2/§1.3 的注册示例相应改为仅 `VulnType.XSS`。

### E3（3.3）：API 客户端不新建文件

`generated.ts`（openapi-typescript 生成）**已包含** `/appmodels/{app_id}/{version}/drift` 路径与 `DriftReport` 类型；前端用 `client.ts` 的 openapi-fetch `api.POST("/appmodels/{app_id}/{version}/drift", ...)` 模式即可。正文 §3.3 第 3 条（新建 `api/appmodels.ts`）作废。

### E4（3.4/3.5）：协议与配置 API 对齐现实

- `ModelBackend` Protocol 是 **`complete(prompt: str) -> str`**（`application/remote_model.py:72-75`），不是正文的 `propose(prompt, *, system)`。`OllamaBackend` 必须实现 `complete`。
- 配置加载函数现实是 `load_backend_from_config(path) -> RemoteOpenAICompatibleBackend`（`infrastructure/llm/config.py:21`，backend≠remote 直接 raise），不是 `load_llm_config()`。扩展此函数支持 ollama/null。
- 新增 **`SECOPTENT_LLM_CONFIG`** env 覆盖配置路径（正文的相对路径 `config/llm.yaml` 依赖 CWD，systemd 部署 CWD 不固定）。
- **优先级链钉死**：`SECOPTENT_LLM_BACKEND` env（ollama/remote/null）> 配置文件 `backend:` 字段 > `MINIMAX_API_KEY` 存在时的 MiniMax fallback > `NullModelBackend`。

### E5（3.6，范围扩大，决策已确认）：无生产调用方 + 顺带补 API 端点

事实更正：`AuditChain.rotate`/`redact_pii` **没有生产调用方**（只有 3 个测试文件调用）；正文所说"signing_keys router 调用点"是 `SigningKeyService.rotate`（Ed25519 签名密钥，`signing_keys.py:58-73`），与审计链无关。linter R3 当前不扫 `audit_chain.py`（范围：canary/oracle_service/nft_scope/rescan_verifier + execution R3b）。

**用户确认范围 = 卫生修复 + API 端点**：
1. 卫生修复（原 3.6）：`rotate(*, session=None)` / `redact_pii(event_id, *, keys, session=None)` 内部透传；linter R3 扩扫 `audit_chain.py`（先红后绿）。
2. API 端点（audit_router，`interfaces/api/routers/audit.py`）：
   - `POST /audit/rotate`（body: `{actor, actor_role}`）→ `audit_chain.rotate(session=请求 session)`；
   - `POST /audit/redact`（body: `{event_id, keys, actor, actor_role}`）→ `audit_chain.redact_pii(event_id, keys=frozenset(keys), session=请求 session)`；
   - 两者 **human-only**（agent 角色 403，模式对齐 `signing_keys.py:70` 的 rotate 门禁）；
   - `app.state.audit_chain` 已在 composition root；响应 schema 新增 `AuditChainEventOut`（event_id/action/event_hash/signature）或复用现有 out。
3. 测试：agent 403 / human 200 / rotate 后 `GET /audit/verify` 仍 valid / redact 后 `GET /audit/events?redacted` 掩码生效（若 export 语义需要则补 redacted 查询参数——以 `AuditChain.export(redacted=True)` 现状为准）/ session 透传不自行 commit（请求事务原子性）。

---

## 1. 3.1 Echo Canary Per-Method Gate

### 1.1 现状（已核实，file:line）

- `domain/verification/models.py::VerificationMethod` 字段：`vuln_type / default_n / retry_strategy / cross_worker / server_error_threshold / oob_window_seconds`。**无 `echo_enabled` 字段**。
- `infrastructure/oracle/verifier_factory.py::RescanVerifierFactory.for_finding`（line 40-65）：构造 scan_kwargs 时**只嵌入 OOB placeholder**（`-u {asset}?cb={OOB_PLACEHOLDER}`），**从不嵌入 echo canary `{{canary_token}}`**。
- `infrastructure/oracle/rescan_verifier.py`（line 115-116）：echo 分支门控 `bool(canary_token) and _contains(self._scan_kwargs, CANARY_PLACEHOLDER)`。由于 factory 从不嵌入 placeholder，**echo 分支是死代码**--反射型 XSS 等只能走 legacy 子串匹配（更宽松，误报风险高）。
- `application/canary.py::CANARY_PLACEHOLDER = "{{canary_token}}"` 已定义，`CanaryTokenManager` 已就绪。

**问题本质**：OOB canary 是"无脑嵌"（URL 参数对非 OOB 发现无害，prefix-match 仍成立），但 echo canary 不能无脑嵌--blanket 嵌入会把所有非 OOB 发现从 legacy 子串匹配切到更严的 echo 验证（要求精确回显 canary），回归非反射型发现。需要 **per-method 门控**：只有反射型 vuln type 才嵌 echo canary。

### 1.2 方案设计

**决策（与路线图一致）**：给 `VerificationMethod` 加 `echo_enabled: bool = False` 字段；`default_registry()` 为反射型 vuln type（XSS reflected、open redirect、SSTI 等）设 `echo_enabled=True`；`for_finding` 仅在 `method.echo_enabled` 时把 `{{canary_token}}` 嵌入 scan_kwargs 的某个参数位。

**备选（否决）**：
- (b) `canary_mode` 枚举 `NONE/ECHO/OOB/BOTH`--更表达力但与现有 `oob_window_seconds`（已编码 OOB 性质）重复，YAGNI。
- (c) 按 vuln_type 推断（隐藏耦合，新加 vuln type 易漏）--否决，显式 flag 更可审计。

**嵌入位置**：echo canary 嵌入 scan_kwargs 的一个新 key `echo_probe`（值 `{{canary_token}}`），rescan_verifier 的 `_contains` 已递归扫描整个 scan_kwargs dict，会命中。不嵌在 -u URL（避免与 OOB placeholder 冲突）；嵌在独立 key 让 rescan_verifier 的 echo 分支明确取这个值作回显匹配。

### 1.3 细节设计

**文件变更**：

1. `src/secopent/domain/verification/models.py`：
```python
@dataclass(frozen=True, slots=True)
class VerificationMethod:
    vuln_type: VulnType
    default_n: int
    retry_strategy: RetryStrategy = RetryStrategy.CROSS_WORKER
    cross_worker: bool = True
    server_error_threshold: int = 2
    oob_window_seconds: int = 0
    echo_enabled: bool = False  # 新增：反射型 vuln 才嵌 echo canary

    def __post_init__(self) -> None:
        if self.default_n < 1:
            raise DomainValidationError(...)
```

2. `src/secopent/domain/verification/registry.py::default_registry()`：为反射型 vuln type 设 `echo_enabled=True`：
```python
VerificationMethod(VulnType.XSS_REFLECTED, default_n=3, echo_enabled=True),
VerificationMethod(VulnType.OPEN_REDIRECT, default_n=3, echo_enabled=True),
VerificationMethod(VulnType.SSTI, default_n=3, echo_enabled=True),
# 其余保持 echo_enabled=False
```
（具体 VulnType 枚举值以 `domain/verification/models.py::VulnType` 现状为准；若 SSTI/OPEN_REDIRECT 不在枚举中，先加枚举值或仅对 XSS_REFLECTED 启用。）

3. `src/secopent/infrastructure/oracle/verifier_factory.py::for_finding`：需要拿到 finding 对应的 VerificationMethod。factory 增加一个 `method_lookup: Callable[[Finding], VerificationMethod | None]` 依赖（或直接注入 `VerificationMethodRegistry`）：
```python
def for_finding(self, finding: Any) -> OracleVerifier:
    ...
    scan_kwargs: dict[str, Any] = {"adapter_key": "nuclei", "args": args}
    method = self._method_registry.method_for(finding)  # 新增
    if method is not None and method.echo_enabled:
        scan_kwargs["echo_probe"] = CANARY_PLACEHOLDER  # 仅反射型嵌
    if self._template_host_dir:
        scan_kwargs["mounts"] = {"/templates": self._template_host_dir}
    return RescanVerifier(...)
```

4. `rescan_verifier.py`：**无需改**。`_contains(self._scan_kwargs, CANARY_PLACEHOLDER)` 已会命中新增的 `echo_probe` key；echo 分支逻辑不变。

**测试**（TDD）：
- `tests/domain/test_verification_method.py`：`echo_enabled` 默认 False；反射型 method 注册为 True。
- `tests/infrastructure/test_verifier_factory.py`：
  - `echo_enabled=True` 的 finding -> scan_kwargs 含 `echo_probe={{canary_token}}`
  - `echo_enabled=False` 的 finding -> scan_kwargs 不含 `echo_probe`
  - OOB placeholder 仍始终嵌入（不回归）
- `tests/oracle_ground_truth/`：XSS reflected 在场 -> echo 路径触发 -> CONFIRM；非反射型 finding 不受 echo canary 影响（仍走 legacy/echo-absent 路径）。

### 1.4 DoD
- [ ] `VerificationMethod.echo_enabled` 字段就位，默认 False
- [ ] 反射型 vuln type（至少 XSS_REFLECTED）注册为 echo_enabled=True
- [ ] `for_finding` 仅 echo_enabled 时嵌 echo canary；OOB canary 嵌入不回归
- [ ] rescan_verifier echo 分支对反射型 finding 实际触发（ground-truth 测试）
- [ ] 非反射型 finding 不受影响（无 echo canary 仍能走 legacy 路径确认）
- [ ] 全量 pytest + ruff + mypy 绿

### 1.5 依赖
- 无外部依赖；`VerificationMethodRegistry.method_for(finding)` 的查找逻辑（按 finding 的 vuln_type）需确认已存在或本次新增。

---

## 2. 3.2 Strix/Shannon 分层集成 ✅ 已完成

**状态**：v0.4.0 已发布。P0-P3（domain/peer_agents + application/peer_agents + harness + StrixBackend/ShannonBackend + AttackChain + 知识移植）+ Phase 2.2（真实镜像 + harness 切换）全部落地。详见 `docs/superpowers/specs/2026-08-04-strix-shannon-layered-integration-design.md` + 6 份实现计划。

**遗留**（Linux 验证项，非阻塞）：strix/shannon 真实 A/B 跑、Shannon 观察门评估。

---

## 3. 3.3 DriftView 前端 UI

### 3.1 现状（已核实）

- 后端就绪：`interfaces/api/routers/appmodels.py:380` `POST /{app_id}/{version}/drift`，schema `DriftRequest` / `DriftReportOut` 已定义；`application/drift_detector.py::DriftDetector.check(current, reimported)` 已实现（返回 `DriftReport` 含 added/removed/changed）。
- 前端缺：W4-E 移除了占位 DriftView tab；`interfaces/web/src/features/case-studio/` 下无 DriftView 组件；`CaseStudio.tsx` 无 Drift tab。

### 3.2 方案设计

**决策**：新建 `DriftView.tsx`（表单输入 re-imported states/transitions -> POST /drift -> 渲染 added/removed/changed 三栏），加回 CaseStudio 的 Drift tab。

**交互流**：
1. 用户在 CaseStudio 选中某 AppModel version
2. 切到 Drift tab -> 表单：粘贴/编辑 re-imported 的 states（一行一个）+ transitions（CSV: from,to,endpoint）
3. 点"检测漂移" -> `POST /{app_id}/{version}/drift` body=`{states, transitions}`
4. 渲染 `DriftReportOut`：Added（绿）/ Removed（红）/ Changed（黄，含 diff）三栏

**备选（否决）**：从 Git 历史 diff 两个 AppModel version 自动填表--YAGNI，当前 drift_detector 是显式 re-import 输入，UI 跟随后端契约即可。

### 3.3 细节设计

**文件变更**：

1. `src/secopent/interfaces/web/src/features/case-studio/DriftView.tsx`（新建）：
   - Props: `appId: string, version: string`
   - State: `reimportedStates: string`（textarea）, `reimportedTransitions: string`（textarea, CSV）, `report: DriftReportOut | null`, `loading: bool`, `error: string | null`
   - 提交：解析 textarea -> `POST /api/appmodels/{appId}/{version}/drift` -> setReport
   - 渲染：三栏 `<ul>`（added/removed/changed），changed 项含旧值->新值
   - 用项目既有 UI 组件（Button/Card/Input--读 `features/case-studio/` 现有组件风格对齐）

2. `src/secopent/interfaces/web/src/pages/CaseStudio.tsx`：加回 Drift tab（tab id `drift`，label "漂移检测"），渲染 `<DriftView appId={...} version={...} />`。匹配现有 tab 注册模式。

3. `src/secopent/interfaces/web/src/api/appmodels.ts`（或同类 API client 文件）：加 `postDrift(appId, version, body)` 函数，返回 `DriftReportOut`。TypeScript 类型从后端 OpenAPI 推导或手写对齐 `DriftRequest/DriftReportOut`。

**测试**：
- 前端无单测框架则靠 build + 手动验证（项目前端测试惯例以 `docs/web/` 为准--先查有无 vitest/jest）。
- 后端 `/drift` 已有测试（`tests/interfaces/test_appmodels.py` 或同类）--不回归。
- 验收：`npm run build` 绿 + 手动跑一次 drift 检测渲染正确。

### 3.4 DoD
- [ ] DriftView.tsx 就位，表单 + 三栏渲染
- [ ] CaseStudio Drift tab 加回
- [ ] `npm run build` 绿
- [ ] 手动验证：粘贴 re-imported 数据 -> 检测 -> 三栏正确显示 added/removed/changed
- [ ] 后端 /drift 测试不回归

### 3.5 依赖
- 无代码依赖；前端 build 工具链可用（`cd src/secopent/interfaces/web && npm install`）。

---

## 4. 3.4 + 3.5 LLM 后端统一（合并设计）

> 3.4（LocalOllama）与 3.5（Multi-Provider Config）紧耦合--都是 LLM 后端选择。合并为一项：**llm.yaml 配置驱动 + ollama 作为可选 provider**。

### 4.1 现状（已核实）

- `interfaces/api/main.py:489-500`：硬编码 `if os.environ.get("MINIMAX_API_KEY"): RemoteOpenAICompatibleBackend(...) else: NullModelBackend()`。**不读 llm.yaml**。
- `config/llm.yaml`：已有 MiniMax/DeepSeek/Qwen 示例（endpoint/api_key_env/model），但**从未被加载**。
- `infrastructure/llm/`：`null_backend.py` + `remote_openai_backend.py` + `config.py`。**无 `ollama_backend.py`**。
- `infrastructure/llm/__init__.py`：docstring 提及 "Phase B+" 预留 ollama。

### 4.2 方案设计

**决策**：`llm.yaml` 的 `backend:` 字段成为单一选择源（`remote` / `ollama` / `null`）；`main.py` 读 config 动态构造后端；新增 `OllamaBackend` 实现 `ModelBackend` 协议。

**config 结构**（llm.yaml，扩展现有）：
```yaml
backend: remote          # remote | ollama | null
# remote:
endpoint: https://api.minimax.chat/v1
api_key_env: MINIMAX_API_KEY
model: abab6.5s-chat
max_tokens: 2048
temperature: 0.2
# ollama (backend: ollama 时用):
# endpoint: http://localhost:11434
# model: llama3.1:8b
```

**后端选择逻辑**（main.py）：
```python
def _build_llm_backend(config_path: Path = Path("config/llm.yaml")) -> ModelBackend:
    cfg = load_llm_config(config_path)  # 已有 infrastructure/llm/config.py
    if cfg.backend == "remote":
        return RemoteOpenAICompatibleBackend(
            endpoint=cfg.endpoint, api_key_env=cfg.api_key_env, model=cfg.model,
        )
    if cfg.backend == "ollama":
        return OllamaBackend(endpoint=cfg.endpoint, model=cfg.model)
    return NullModelBackend()
```

**env 覆盖**（保留）：`SECOPTENT_LLM_BACKEND=ollama` 覆盖 config（部署灵活性）。

### 4.3 细节设计

**文件变更**：

1. `src/secopent/infrastructure/llm/ollama_backend.py`（新建）：
```python
class OllamaBackend:
    """Local Ollama backend (http://localhost:11434/api/generate).

    No API key, no egress to cloud.适合 air-gapped / 成本敏感场景。
    Implements ModelBackend: propose() calls Ollama generate API.
    """
    def __init__(self, *, endpoint: str = "http://localhost:11434",
                 model: str = "llama3.1:8b", timeout: float = 60.0) -> None: ...

    def propose(self, prompt: str, *, system: str | None = None) -> str:
        # POST {endpoint}/api/generate {model, prompt, stream: false}
        # return response["response"]
```
   - 实现 `ModelBackend` Protocol（读 `application/remote_model.py::ModelBackend` 确切方法签名对齐）。
   - 走 `httpx`（项目已有依赖）；无 stream（简单先做）；timeout 可配。

2. `src/secopent/infrastructure/llm/config.py`：扩展 `LlmConfig` dataclass 加 `backend: str` 字段 + `load_llm_config()` 解析新字段。

3. `src/secopent/interfaces/api/main.py:489-500`：替换硬编码为 `_build_llm_backend()` 调用；env `SECOPTENT_LLM_BACKEND` 覆盖；env `MINIMAX_API_KEY` 仍作向后兼容 fallback（若 config 未指定且 MINIMAX_API_KEY 在，用 MiniMax remote）。

4. `config/llm.yaml`：补 ollama 段注释示例（默认仍 remote/MiniMax）。

**测试**（TDD）：
- `tests/infrastructure/test_ollama_backend.py`：mock httpx -> propose() 返回 response；timeout 处理；endpoint 缺省。
- `tests/infrastructure/test_llm_config.py`：解析 `backend: ollama` 段；env 覆盖优先级。
- `tests/interfaces/test_main_llm_selection.py`：`backend: remote` -> RemoteOpenAICompatibleBackend；`backend: ollama` -> OllamaBackend；`backend: null` -> NullModelBackend；env 覆盖。

### 4.4 DoD
- [ ] `OllamaBackend` 实现 ModelBackend，httpx mock 测试绿
- [ ] `llm.yaml` `backend:` 字段驱动选择；env `SECOPTENT_LLM_BACKEND` 覆盖
- [ ] 向后兼容：无 config 时 MINIMAX_API_KEY 仍触发 remote（不回归现有部署）
- [ ] 三后端选择测试绿
- [ ] 全量 pytest + ruff + mypy 绿

### 4.5 依赖
- httpx 已在依赖；Ollama 本体由 operator 部署（`ollama serve`，文档说明）。

---

## 5. 3.6 rotate/redact_pii Session Threading

### 5.1 现状（已核实）

- `application/audit_chain.py`：
  - `record(*, session=None)`（line 75-118）--**已支持 session**（v4 same-tx refactor 成果）。
  - `record_permit_nonce(*, session=None)`（line 121）--已支持。
  - `rotate(self) -> SignedAuditEvent`（line 158）--**签名无 session**。
  - `redact_pii(self, event_id, *, keys) -> SignedAuditEvent`（line 168）--**签名无 session**。
- 两者内部调 `self.record(...)` 不传 session（推测--需读实现体确认；若 rotate/redact_pii 不在 daemon 热路径则 Phase 1 T2 RLock 修复未覆盖，但仍是 v3/v4 bug class 残留）。
- `scripts/lint_forbidden_patterns.py` R3 规则：audit `.record()` 必须带 `session=`。**若 rotate/redact_pii 内部 record 不传 session，linter 应已报错**--需确认 linter 是否扫描 audit_chain.py 内部调用（可能只扫 router 层）。

### 5.2 方案设计

**决策**：`rotate(session=None)` + `redact_pii(*, keys, session=None)` -> 内部 `self.record(..., session=session)`；调用方（`signing_keys` router 等）传 session。

**与 forbidden linter 对齐**：先跑 `python scripts/lint_forbidden_patterns.py` 看是否已报 rotate/redact_pii 的违规。若是，本项 = 修 lint 报错；若否，扩展 linter 覆盖 audit_chain.py 内部 record 调用。

### 5.3 细节设计

**文件变更**：

1. `src/secopent/application/audit_chain.py`：
```python
def rotate(self, *, session: Any = None) -> SignedAuditEvent:
    ...
    return self.record(action="rotate", ..., session=session)

def redact_pii(self, event_id: str, *, keys: frozenset[str],
               session: Any = None) -> SignedAuditEvent:
    ...
    return self.record(action="redact_pii", ..., session=session)
```

2. 调用方（grep `rotate(` / `redact_pii(` 找到 router/service 层调用点）传 session：典型在 `signing_keys` router 的 rotate 端点 + redact 端点。

3. `scripts/lint_forbidden_patterns.py`：若 linter 未覆盖 audit_chain.py 内部 record 调用，扩展 R3 规则的扫描范围（或确认 R3 已覆盖，仅修违规）。

**测试**（TDD）：
- `tests/application/test_audit_chain.py`：
  - `rotate(session=fake_session)` -> record 收到 session（不自己 commit）
  - `rotate()` 默认 session=None -> 走原自管事务路径（不回归）
  - `redact_pii(session=...)` 同理
  - 并发 rotate（RLock 仍持有--Phase 1 T2 不回归）

### 5.4 DoD
- [ ] `rotate` / `redact_pii` 签名加 `session=None`
- [ ] 内部 record 透传 session
- [ ] 调用方传 session
- [ ] forbidden linter 对 audit_chain.py 内部 record 调用绿
- [ ] 并发测试不回归（RLock 完整性）
- [ ] 全量 pytest + ruff + mypy 绿

### 5.5 依赖
- forbidden linter（Phase 1 T1）已就绪；本项与之对齐。

---

## 6. 风险与缓解

| 风险 | 缓解 |
|------|------|
| 3.1 改 VerificationMethod 字段影响序列化/持久化 | frozen dataclass 加字段默认值，向后兼容；检查 ORM 模型（若有 verification_methods 表）是否需迁移 |
| 3.1 echo canary 嵌入位置不当导致 nuclei 模板解析失败 | 嵌在独立 `echo_probe` key（非 -u URL），rescan_verifier 递归扫描命中；ground-truth 测试把关 |
| 3.3 前端 build 工具链版本漂移 | 先 `npm install` 确认 lockfile 一致；build 失败不阻塞后端发版（前端独立构建） |
| 3.4 Ollama 无 API key，但 RemoteModelGateway 的脱敏/审计/分类规则依赖云端模型元数据 | OllamaBackend 走同一 ModelBackend 协议，RemoteModelGateway 的脱敏前置仍生效（本地模型也脱敏）；审计记 backend=ollama |
| 3.5 向后兼容：现有部署靠 MINIMAX_API_KEY env 触发 | `_build_llm_backend` 保留 env fallback：无 config 时 MINIMAX_API_KEY -> remote(MiniMax) |
| 3.6 rotate/redact_pii 改签名影响外部调用 | session=None 默认值，向后兼容；调用方逐个改 |

---

## 7. 交接清单（执行者 checklist）

执行者按本文件逐项 TDD 实现，每项独立 commit，全部完成后发 v0.5.0。

### 执行序
1. **3.6**（0.5d，P2，安全相关）-- 先跑 forbidden linter 确认覆盖范围，改 rotate/redact_pii 签名 + 调用方
2. **3.1**（1d，P2）-- VerificationMethod.echo_enabled + registry + verifier_factory 门控
3. **3.4+3.5**（1.5d，P3）-- OllamaBackend + llm.yaml 配置驱动 + main.py 选择逻辑
4. **3.3**（1d，P3）-- DriftView.tsx + CaseStudio tab（可与 3.4/3.5 并行）
5. 全量门禁（pytest + ruff + mypy + `git diff --check`）+ CHANGELOG + 发 v0.5.0

### 每项 DoD 自检
- [ ] 现状核实（file:line 与本文件一致；若代码已变，同步更新设计）
- [ ] TDD：测试先行 -> 红 -> 实现 -> 绿
- [ ] 全量 pytest + ruff + mypy 绿（零回归）
- [ ] 独立 commit，conventional 格式（`feat(...)` / `fix(...)` / `refactor(...)`）
- [ ] 设计偏差写 ADR 或本文件勘误

### 发版
- CHANGELOG `[Unreleased]` 填 Phase 3 内容 -> `scripts/release.sh 0.5.0`
- 更新 `docs/architecture/handoff-roadmap.md` Phase 3 状态 -> ✅ 已发布 v0.5.0

---

## 8. 不做（YAGNI / 超范围）

- ❌ LLM 流式输出（stream=true）--当前 propose() 一次性返回，YAGNI
- ❌ Ollama 模型自动拉取（`ollama pull`）--operator 动作
- ❌ DriftView 的 Git 历史自动 diff --后端契约是显式 re-import
- ❌ VerificationMethod 的 `canary_mode` 枚举--`echo_enabled` + `oob_window_seconds` 已够表达
- ❌ Phase 4（部署清单 + C1 安全）--本文件只覆盖 Phase 3

---

## 9. 已知关联问题

- **`GET /catalog/latest` 偶发 200-null**（v0.4.0 release notes 已记，根因调查中，非 Phase 3 范围）。若 3.6 路过 audit_chain 相关代码时发现线索，顺手记录但不阻塞 Phase 3。
