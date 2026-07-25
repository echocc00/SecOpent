# M5 安全加固+Beta 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** 实现 ScopeEnforcer（10 步执行链+双校验）+ SecretStore + AuditChain 完整（密钥管理+Permit nonce+Log rotation 续链+GDPR 保留）+ EmergencyStop + RemoteModelGateway（含 LLM 运营约束）+ PromptInjectionGuard + 完整 Scoped Egress + PostgreSQL Contract 切换 + E2E + CI + STRIDE 威胁建模，达到 Beta。

**Architecture:** 安全加固在 M4 全链路就绪后做。ScopeEnforcer 复用 M0 PolicyEngine 扩展 10 步执行链（含 DNS 二次校验防 rebinding）。AuditChain 从 M0 hash chain 升级到完整（Ed25519 签名+密钥管理+Permit nonce+Log rotation 续链+GDPR 数据保留）。Scoped Egress 完整（HTTP 代理+TCP netns+nftables，V1 单机仍强制）。PostgreSQL Contract 验证 Repository 抽象（M0 预留）。

**Tech Stack:** Python 3.11+, cryptography (Ed25519), iptables/nftables, pyroute2 (netns), Redis（V2，M5 仅评估）, PostgreSQL, GitHub Actions, ruff, mypy, pytest-cov.

**DoD（对应主设计 §13 M5）:**
- 全安全条件通过（§16.2 的 14 条必须通过）
- E2E 绿（Juice Shop/crAPI/httpbin）
- Lite 2C2G 可跑
- PG Contract 通过
- STRIDE 威胁模型归档

**依赖：** M0-M4 全部就绪

**参考：** 主设计 §12（安全）/§6.7（分布式，V2）；ADR-016/017

---

## 0. 文件结构

```text
src/secopent/
  domain/
    permits/
      models.py          # ExecutionPermit（签名短时+nonce+绑定）
    secrets/
      models.py          # SecretMetadata（secret_ref only）
  application/
    scope_enforcer.py    # ScopeEnforcer（10 步执行链+双校验+DNS 二次校验）
    secret_store.py      # SecretStore（keyring/加密文件/KMS 抽象）
    audit_chain.py       # AuditChain 完整（密钥+nonce+rotation 续链+保留）
    emergency_stop.py    # EmergencyStop
    remote_model.py      # RemoteModelGateway（分级+脱敏+授权+审计+运营约束）
    prompt_injection.py  # PromptInjectionGuard
  infrastructure/
    egress/
      http_proxy.py      # Scoped HTTP 代理
      tcp_netns.py       # TCP netns + nftables
      dns_rebind.py      # DNS 二次校验防 rebinding
    secrets/
      keyring_backend.py, encrypted_file_backend.py, kms_backend.py
    audit/
      key_manager.py     # Ed25519 密钥管理
      rotation.py        # Log rotation 续链
      retention.py       # GDPR 数据保留
    permits/
      permit_signer.py   # Ed25519 Permit 签名/验签
  execution/
    network_policy/      # （V1 单机仍强制 scoped egress）
tests/
  security/
    test_scope_enforcer.py, test_permit_replay.py, test_prompt_injection.py
    test_dns_rebinding.py, test_secret_isolation.py, test_sandbox_escape.py
    test_audit_tamper.py, test_emergency_stop.py
  e2e/
    test_juice_shop_full.py, test_crapi_full.py, test_httpbin_full.py
  infrastructure/
    test_pg_contract.py, test_scoped_egress.py
.github/workflows/ci.yml
docs/security/threat-model.md  # STRIDE
```

---

## Task 1: ScopeEnforcer（10 步执行链 + 双校验）

**Files:** `application/scope_enforcer.py`, `tests/security/test_scope_enforcer.py`

- [ ] **Step 1: 测试** - 10 步执行链（Target Normalize->Explicit Deny->Include Match->DNS Resolve->Resolved IP Recheck->Port/URL->Time Window->Risk->Approval->Budget->Permit）；Deny 优先；DNS 解析后二次校验防 rebinding（解析 IP 再查 scope）；API + 执行层双校验；Scope 外地址在执行层网络层被拒
- [ ] **Step 3: 实现** - ScopeEnforcer.check(action, scope_snapshot) -> PolicyDecision；复用 M0 PolicyEngine 扩展 10 步；DNS resolve 后 IP recheck（防 DNS rebinding 到内网/Scope 外）；API 层 + 执行层（AdapterRunner）双校验
- [ ] **Step 5: 提交** `feat(security): add scope enforcer with 10 step chain`

## Task 2: ExecutionPermit（签名短时 + nonce）

**Files:** `domain/permits/models.py`, `infrastructure/permits/permit_signer.py`, `tests/security/test_permit_replay.py`

- [ ] **Step 1: 测试** - Permit 签名短时（默认 15min）；绑定 Job/Worker/Scope/Plan/Capability/预算/nonce；过期/重放/跨 Worker 拒绝；Ed25519 签名验签
- [ ] **Step 3: 实现** - ExecutionPermit dataclass（job_id/worker_id/scope_digest/plan_digest/capabilities/budget/expires_at/nonce/signature）；PermitSigner 签发/验签；过期拒绝；nonce 防重放；跨 Worker 拒绝
- [ ] **Step 5: 提交** `feat(permits): add signed short-lived execution permit`

## Task 3: SecretStore（keyring/加密文件/KMS）

**Files:** `application/secret_store.py`, `domain/secrets/models.py`, `infrastructure/secrets/*`, `tests/security/test_secret_isolation.py`

- [ ] **Step 1: 测试** - 任务只用 secret_ref，明文不入库；后端 keyring/加密文件/KMS；不进入 Prompt/Case/日志/Evidence/报告；执行时短时文件描述符/内存管道/Secret Mount 注入；任务完成撤销；凭证访问写审计
- [ ] **Step 3: 实现** - SecretStore 抽象（Protocol）；KeyringBackend/EncryptedFileBackend/KmsBackend；resolve(secret_ref) -> 短时注入；任务完成撤销；日志自动脱敏（secret 模式）；审计 secret 使用
- [ ] **Step 5: 提交** `feat(secrets): add secret store with redaction`

## Task 4: AuditChain 完整（密钥管理 + Permit nonce + Log rotation 续链 + GDPR 保留）

**Files:** `application/audit_chain.py`, `infrastructure/audit/key_manager.py`, `rotation.py`, `retention.py`, `tests/security/test_audit_tamper.py`

- [ ] **Step 1: 测试** - Ed25519 签名密钥独立于 Update Bundle 密钥；OS Keyring 存私钥；公钥随报告导出供第三方验证；Permit nonce + 短时；Audit 记录 Permit nonce，重放可检测；Log rotation 时旧链尾哈希写入新链首（previous_chain_tail_hash），不直接断链；GDPR 删除请求时删除 PII 明文但保留 hash + 删除审计记录；保留期可配（默认 90 天 Audit 滚动 + 1 年归档）
- [ ] **Step 3: 实现** - AuditKeyManager（Ed25519，OS Keyring 存私钥）；AuditChain 从 M0 hash chain 升级（加签名）；Permit nonce 记录；Rotation 续链；Retention 策略；GDPR 删除流程
- [ ] **Step 5: 提交** `feat(audit): add full audit chain with key management and retention`

## Task 5: EmergencyStop

**Files:** `application/emergency_stop.py`, `tests/security/test_emergency_stop.py`

- [ ] **Step 1: 测试** - 停止签发新 Permit；撤销未使用 Permit；终止活动容器；保留已产生 Evidence；写高优先级 Audit
- [ ] **Step 3: 实现** - EmergencyStop.trigger() -> 全局开关；Permit 撤销；容器终止（Docker SDK）；Evidence 保留；Audit 高优先级事件
- [ ] **Step 5: 提交** `feat(emergency): add emergency stop`

## Task 6: RemoteModelGateway（分级 + 脱敏 + 授权 + 审计 + LLM 运营约束）

**Files:** `application/remote_model.py`, `tests/security/test_remote_model.py`

- [ ] **Step 1: 测试** - 数据分级 Public/Internal/Sensitive/Restricted/Secret；远程调用统一经 Data Classification->Redaction->Policy->User Consent->Audit；Secret 永不发送；Restricted 默认禁止；Sensitive 默认脱敏；本地模式不依赖 LLM 也能执行扫描；**LLM 运营约束（§12.11）**：本地优先（Ollama/vLLM 7B-13B）+ 远程可选（Claude/GPT API）；每日 Token 预算（默认 500K/天）；速率限制（10 req/min）；Prompt size 上限（32K）；月度计费上限；超限降级本地；告警阈值（80% 预警/100% 降级）
- [ ] **Step 3: 实现** - RemoteModelGateway.call(prompt, data_classification)；分级过滤+脱敏+授权+审计；本地模型 Ollama/vLLM 适配；远程 API 适配；预算/限速/降级规则；告警
- [ ] **Step 5: 提交** `feat(llm): add remote model gateway with operational constraints`

## Task 7: PromptInjectionGuard

**Files:** `application/prompt_injection.py`, `tests/security/test_prompt_injection.py`

- [ ] **Step 1: 测试** - 目标页面/Banner/工具输出/漏洞描述标记 untrusted_target_output；Agent 输出转结构化 Action，经 Schema/Scope/Policy/Approval/Registry；目标内容不能改策略/Scope/用例状态/Secret/审批；Prompt Injection 测试不能改变 Plan
- [ ] **Step 3: 实现** - PromptInjectionGuard 标记 untrusted 内容；Agent 输出强制结构化 Action；Policy Engine 拦截越界；测试用例（注入目标输出尝试改 scope，应被拒）
- [ ] **Step 5: 提交** `feat(security): add prompt injection guard`

## Task 8: Scoped Egress（HTTP 代理 + TCP netns + nftables）

**Files:** `infrastructure/egress/http_proxy.py`, `tcp_netns.py`, `dns_rebind.py`, `tests/infrastructure/test_scoped_egress.py`

- [ ] **Step 1: 测试** - HTTP 工具经 Scoped Egress Proxy；原始 TCP 工具用 netns + nftables；仅 in-scope IP/端口；阻断控制面/DB/Docker host/云 metadata（169.254.169.254）/Scope 外目标；DNS rebinding 防护
- [ ] **Step 3: 实现** - ScopedHttpProxy（mitmproxy 或自建，scope 校验）；TcpNetns（pyroute2 创建 netns + nftables 规则）；DnsRebindGuard（解析后 IP recheck）；云 metadata IP 必阻
- [ ] **Step 5: 提交** `feat(egress): add scoped egress with netns and nftables`

## Task 9: PostgreSQL Contract 切换验证

**Files:** `infrastructure/db/postgres.py`, `tests/infrastructure/test_pg_contract.py`

- [ ] **Step 1: 测试** - PostgreSQL Repository 同一组 Contract 测试通过（M0 预留接口）；业务代码不依赖 SQLite 专有逻辑；FTS5 -> PG full-text；切换无重构
- [ ] **Step 3: 实现** - PostgresEngine（SQLAlchemy PG）；PG full-text 索引（替代 FTS5）；Repository Contract 测试套件跑双后端
- [ ] **Step 5: 提交** `feat(infra): add postgresql contract`

## Task 10: E2E 全链路测试（Juice Shop/crAPI/httpbin）

**Files:** `tests/e2e/test_juice_shop_full.py`, `test_crapi_full.py`, `test_httpbin_full.py`

- [ ] **Step 1: 测试** - E2E：Juice Shop（Web 应用）全链路（recon->scan->verify->report）；crAPI（API）；httpbin（基础）；覆盖矩阵全绿；oracle 验证；报告生成；scope 强制；审计链完整
- [ ] **Step 3: 实现** - docker-compose 起靶场；全链路跑；断言覆盖矩阵/oracle/报告/审计
- [ ] **Step 5: 提交** `test(e2e): add full end to end with three ranges`

## Task 11: STRIDE 威胁建模

**Files:** `docs/security/threat-model.md`

- [ ] **Step 1: 写威胁模型** - STRIDE 6 类（Spoofing/Tampering/Repudiation/Information Disclosure/Denial of Service/Elevation of Privilege）；每类映射到设计组件；Open items 全部归档为具体行动
- [ ] **Step 2: 提交** `docs(security): archive stride threat model`

## Task 12: CI（GitHub Actions）

**Files:** `.github/workflows/ci.yml`

- [ ] **Step 1: CI 配置** - jobs = lint（ruff）/ type（mypy strict for domain/application）/ test-py3.11 / test-py3.12 / compose-smoke（docker compose up + curl /healthz + pytest -m smoke）；覆盖率 70%（逐步提 80）；编码卫生（BOM/控制字符扫描全仓库）
- [ ] **Step 2: CI 绿** - push 后 CI 全绿
- [ ] **Step 3: 提交** `ci: add github actions workflow`

## Task 13: 安全条件验收（§16.2 的 14 条）

**Files:** `tests/security/test_security_conditions.py`

- [ ] **Step 1: 测试 14 条必须通过**：
  1. Scope 外地址在执行层网络层被拒
  2. DNS 解析结果重新校验
  3. Agent 不能执行任意 Shell
  4. 未批准 Active/Intrusive Case 被拒绝
  5. 过期或跨 Worker Permit 被拒绝
  6. 工具不能访问数据库、Docker Host、云 Metadata
  7. Secret 不出现在日志、Evidence、MCP
  8. Prompt Injection 不能改变 Plan
  9. Python Plugin 不能访问 Docker Socket
  10. 远程模型发送前完成脱敏和授权
  11. Emergency Stop 停止活动任务
  12. Audit Hash Chain 断裂可检测
  13. 错误签名 Bundle 被拒绝
  14. 历史 Assessment 固定所有版本
- [ ] **Step 2: 全绿** `test(security): 14 security conditions green`
- [ ] **Step 3: 提交** `test(security): verify 14 mandatory conditions`

## Task 14: M5 质量门 + Beta 发布

- [ ] ruff check 0 errors, mypy strict 0 errors（domain/application/infrastructure）
- [ ] pytest --cov=src --cov-fail-under=70 全绿
- [ ] docker compose up -d 后 curl /healthz 200
- [ ] E2E 三靶场全绿
- [ ] 14 安全条件全绿
- [ ] PG Contract 通过
- [ ] STRIDE 归档
- [ ] 编码卫生扫描全仓库
- [ ] `git tag v0.1.0-beta1` + Release notes
- [ ] 提交 `release(m5): beta 1`

---

## M5 最终验收（Beta DoD）

- [ ] ScopeEnforcer 10 步执行链 + DNS 二次校验 + 双校验
- [ ] ExecutionPermit 签名短时 + nonce + 重放拒绝
- [ ] SecretStore 不入库/Prompt/日志/Evidence/报告
- [ ] AuditChain 完整（密钥+nonce+rotation 续链+GDPR 保留）
- [ ] EmergencyStop 撤销 Permit + 终止容器
- [ ] RemoteModelGateway 分级+脱敏+授权+审计+LLM 运营约束
- [ ] PromptInjectionGuard untrusted 标记 + 结构化 Action
- [ ] Scoped Egress（HTTP 代理 + TCP netns + nftables + 云 metadata 必阻）
- [ ] PostgreSQL Contract 通过
- [ ] E2E（Juice Shop/crAPI/httpbin）全绿
- [ ] 14 安全条件全绿
- [ ] STRIDE 威胁模型归档
- [ ] CI（ruff/mypy/pytest/compose smoke/编码卫生）全绿
- [ ] Lite 2C2G 可跑，Standalone 4C8G 可跑
- [ ] 覆盖率 ≥70%
- [ ] `git tag v0.1.0-beta1` 发布

## V1 完成定义（§15 全部 35 项在此里程碑闭环）

M5 通过后，V1 Beta 达成。所有 §15 DoD 项闭环：
- Agent 端到端编排 ✅（M4）
- 目录驱动覆盖 + 覆盖矩阵门禁 ✅（M1/M4）
- oracle N/N 验证 + 靶场集回归 ✅（M2）
- 四域 Adapter Pack（含 dalfox/RESTler/Schemathesis/ZAP）✅（M1）
- AppModel 模型驱动 5 类逻辑测试 ✅（M3）
- OOB 自托管 Interactsh ✅（M2）
- pentest-ai OracleEngine 采纳 ✅（M2）
- 自定义 POC Nuclei YAML + Python 沙箱 ✅（M2）
- Custom POC 晋升 TestCatalog ✅（M1）
- Scope 强制 + Secret + Audit + EmergencyStop ✅（M0/M5）
- LLM 运营约束 + Redaction 延伸 Report ✅（M5/M4）
- MCP 供应链 trust level ✅（M4）
- Repository SQLite/PG ✅（M0/M5）
- 完整 Scoped Egress + Update Bundle ✅（M5/M1）
- E2E + CI 全绿 ✅（M5）
- STRIDE 归档 ✅（M5）

## V2 预留（V1 不做，§22.4）

- 远程 Worker 分布式（§6.7 spec 已备）
- 竞态/角色逻辑测试
- 多租户 SaaS / 团队协作 / 客户门户
- K8s 调度 / 插件市场

---

## 项目完成

V1 Beta 交付后，进入：
1. **内部验证**：单兵实际渗透测试场景验证差异化（§22.1 市场实验）
2. **社区反馈**：聚合层 + CoverageMatrix 开源聚社区（§7.6）
3. **V2 规划**：远程 Worker / 多租户 / ToB 平台（§22.4）

总工期：M0-M5 共 45-68 工程日 + 缓冲 = **4-6 月**单人全职。
