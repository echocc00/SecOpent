# M2 验证+用例引擎 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** 采纳 pentest-ai 作 OracleEngine + 建 VerificationMethodRegistry 策展层 + 自托管 Interactsh OOB + oracle ground-truth 靶场集 + CaseEngine（YAML Nuclei 兼容+扩展）+ PythonPluginSandbox + CaseRegistry + RiskAnalyzer + FixtureRunner，实现确定性验证流水线和自定义 POC 引擎。

**Architecture:** OracleEngine 采纳 pentest-ai（MIT，pip install ptai），不自建；VerificationMethodRegistry 是策展层（漏洞类型->验证方法+N+重跑策略+5xx 阈值）覆盖 ptai 之上。CaseEngine 用 Nuclei YAML 基础+扩展（canary_token/verification/classification 钩子），内部 AST 解析不用 eval。PythonPluginSandbox 用 gVisor 或 seccomp profile（M2 锁定方案）。Interactsh 自托管（Docker，国内公共 OOB 不稳）。

**Tech Stack:** Python 3.11+, pentest-ai (ptai), interactsh-client, Docker SDK, PyYAML, jinja2, seccomp/gVisor, pydantic v2, pytest.

**DoD（对应主设计 §13 M2）:**
- oracle N/N 生效（采纳 ptai + VerificationMethodRegistry）
- YAML Case 可执行可校验（Nuclei 兼容+扩展）
- Python 沙箱隔离（gVisor 或 seccomp，M2 锁定）
- 风险分析门禁（RiskAnalyzer 静态分析）
- oracle 自身可在靶场集上验证（Juice Shop/crAPI/vulhub）

**依赖：** M0（Scope/Policy/Repository/Audit）+ M1（AdapterOutput/Observation/CoverageMatrix）

**参考：** 主设计 §9（验证）/§11（POC）；ADR-004/005/006/014

---

## 0. 文件结构

```text
src/secopent/
  domain/
    verification/
      models.py          # VerificationMethod, VerificationResult, CandidateFinding, ConfirmedFinding
      registry.py        # VerificationMethodRegistry（漏洞类型->方法+N+策略+5xx 阈值）
    cases/
      models.py          # CaseDefinition, CaseVersion, CaseStatus, CaseOrigin
      yaml_schema.py     # Nuclei YAML + 扩展（canary_token/verification/classification）
      risk.py            # RiskClass 计算（GET=Low/扫描=Active/凭据=Intrusive/Shell=拒绝）
    evidence/
      models.py          # Evidence（RAW/REDACTED/SUMMARY 三层, CAS sha256）
  application/
    oracle.py            # OracleEngine（采纳 ptai + VerificationMethodRegistry 策展）
    canary.py            # CanaryTokenManager（唯一 token 生成/校验/审计）
    cases.py             # CaseService（生命周期 + validate + dry_run）
    evidence.py          # EvidenceService（CAS + redaction）
    risk_analyzer.py     # RiskAnalyzer（静态风险分析，发布门禁）
    fixture_runner.py    # FixtureRunner（5 类 fixture 校验）
  infrastructure/
    oracle/
      ptai_adapter.py    # pentest-ai 适配层
      interactsh.py      # 自托管 Interactsh 客户端
    sandbox/
      python_sandbox.py  # PythonPluginSandbox（gVisor 或 seccomp）
      case_context.py    # CaseContext SDK（scoped_http/scoped_tcp/credential_ref/temp_fs/oast）
    case_engine/
      yaml_parser.py     # Nuclei YAML + 扩展 parser
      ast_evaluator.py   # 内部 AST（不用 eval）
      interpreter.py     # DSL interpreter（dns/tcp/tls/http/extract/transform/compare/condition/foreach/retry/wait）
    evidence_store/
      local_cas.py       # Local CAS（sha256/<prefix>/<digest>）
      redaction.py       # RedactionEngine（regex + 我方/目标 secret 区分）
tests/
  domain/test_verification.py, test_cases.py, test_evidence.py
  application/test_oracle.py, test_canary.py, test_case_service.py, test_risk_analyzer.py
  infrastructure/test_ptai_adapter.py, test_interactsh.py, test_python_sandbox.py, test_yaml_parser.py
  oracle_ground_truth/
    test_juice_shop.py, test_crapi.py, test_vulhub.py
```

---

## Task 1: VerificationMethodRegistry Domain

**Files:** `domain/verification/models.py`, `domain/verification/registry.py`, `tests/domain/test_verification.py`

- [ ] **Step 1: 测试** - VerificationMethod（vuln_type/n/default_N/retry_strategy/cross_worker/5xx_threshold/oob_window）；CandidateFinding（observation_id/status）；ConfirmedFinding（evidence_ids/verified_at）；VerificationMethodRegistry 按 vuln_type 查方法
- [ ] **Step 3: 实现** - 14 类漏洞方法（SQLi/RCE/SSRF/XXE/XSS/反序列化/文件读/认证绕过/路径穿越/IDOR/参数篡改/MFA 跳过/弱凭证/越权）；每类 N 值（SQLi 延时 N=5，RCE echo N=3，OOB N=3+窗口）；retry_strategy（cross_worker 默认，同 Worker 间隔 2s 降级）；5xx_threshold（2 次连续 INCONCLUSIVE 升级人审）
- [ ] **Step 5: 提交** `feat(verification): add method registry with n and retry strategy`

## Task 2: pentest-ai OracleEngine 适配

**Files:** `infrastructure/oracle/ptai_adapter.py`, `application/oracle.py`, `tests/infrastructure/test_ptai_adapter.py`

- [ ] **Step 1: 测试** - PtaiAdapter.verify(candidate, method) -> VerificationResult；N 次独立复现；canary token 注入；mock ptai 返回；N/N->Confirmed/失败->REFUTED/部分->INCONCLUSIVE；5xx 计 INCONCLUSIVE 不计 REFUTED
- [ ] **Step 3: 实现** - `pip install ptai`；PtaiAdapter 包装 ptai API；OracleEngine.verify(candidate) 从 VerificationMethodRegistry 查方法 -> 调 ptai 执行 N 次 -> 聚合结果；LLM 永不标记 Confirmed（只有 oracle）
- [ ] **Step 5: 提交** `feat(oracle): adopt pentest-ai with method registry curation`

## Task 3: CanaryTokenManager

**Files:** `application/canary.py`, `tests/application/test_canary.py`

- [ ] **Step 1: 测试** - 每次验证发唯一 token（高熵随机，一次性）；token 嵌入探针（echo/OOB 子域）；确认要求回显；token 不重用；全审计
- [ ] **Step 3: 实现** - CanaryTokenManager.generate() -> token（secrets.token_urlsafe(16)）；embed(command, token)；verify_echo(response, token)；OOB 子域 `<token>.oast.example.com`；审计每个 token 生成/校验
- [ ] **Step 5: 提交** `feat(canary): add canary token manager`

## Task 4: 自托管 Interactsh OOB

**Files:** `infrastructure/oracle/interactsh.py`, `tests/infrastructure/test_interactsh.py`

- [ ] **Step 1: 测试** - InteractshClient 分配唯一回调域；DNS/HTTP/SMTP 回调捕获；canary token 关联回调；自托管 server 配置（Docker）
- [ ] **Step 3: 实现** - 自托管 interactsh-server（Docker，公网 VPS+域名 NS 委托，或内网 DNS 指向）；InteractshClient 注册回调域；poll 回调日志；canary token 作子域关联；离线/内网场景内网 DNS 指向
- [ ] **Step 5: 提交** `feat(oob): add self-hosted interactsh client`

## Task 5: oracle ground-truth 靶场集

**Files:** `tests/oracle_ground_truth/test_juice_shop.py`, `test_crapi.py`, `test_vulhub.py`

- [ ] **Step 1: 测试** - Juice Shop（Web 应用类）已知漏洞 oracle 回归；crAPI（API 类）；vulhub（CVE 复现类）；oracle 升级时在靶场集回归，确保不误判
- [ ] **Step 3: 实现** - docker-compose 起靶场；oracle 对已知漏洞跑 N/N；预期 Confirmed；对非漏洞跑；预期 REFUTED；靶场集作为 oracle 测试 fixture
- [ ] **Step 5: 提交** `test(oracle): add ground truth range regression`

## Task 6: Case Domain + YAML Schema（Nuclei 兼容+扩展）

**Files:** `domain/cases/models.py`, `domain/cases/yaml_schema.py`, `tests/domain/test_cases.py`

- [ ] **Step 1: 测试** - CaseDefinition（id/version/author/risk/target_type/schema/steps/assertions/evidence_req/cwe/cve/owasp/signature/min_engine_version）；CaseStatus（DRAFT->VALIDATED->REVIEWED->SIGNED->PUBLISHED）；CaseOrigin（manual/model_generated/community）；YAML schema 解析 Nuclei 基础+扩展（canary_token 占位/verification 块/classification）
- [ ] **Step 3: 实现** - pydantic v2 CaseDefinition；YAML parser 兼容 Nuclei 语法；扩展钩子：`{{canary_token}}` 占位、`verification: {method, reproduce}` 块、`classification: {cwe, cve, owasp}`；schema 校验
- [ ] **Step 5: 提交** `feat(cases): add case definition and yaml schema`

## Task 7: CaseEngine YAML DSL（AST + interpreter）

**Files:** `infrastructure/case_engine/yaml_parser.py`, `ast_evaluator.py`, `interpreter.py`, `tests/infrastructure/test_yaml_parser.py`

- [ ] **Step 1: 测试** - DSL actions（dns.resolve/tcp.connect/tls.inspect/http.request/http.compare/oast.allocate/oast.wait/extract.regex/jsonpath/xpath/transform.base64/urlencode/hash/compare.text/numeric/timing/condition/foreach/retry/wait）；foreach/retry/wait 硬上限；禁止递归/无限循环/Shell/动态 import/Scope 外目标；断言用内部 AST 不用 eval
- [ ] **Step 3: 实现** - YAML -> AST（自定义节点类型）；AST evaluator（不用 Python eval，内部比较/contains/matches/逻辑/长度/时间差）；interpreter 执行 actions；foreach/retry/wait 硬上限校验；Scope 外目标拒绝
- [ ] **Step 5: 提交** `feat(case-engine): add yaml dsl ast interpreter`

## Task 8: RiskAnalyzer（静态风险分析，发布门禁）

**Files:** `application/risk_analyzer.py`, `domain/cases/risk.py`, `tests/application/test_risk_analyzer.py`

- [ ] **Step 1: 测试** - GET/HEAD=Low；全面扫描/爬虫=Active；凭据/上传/时间差/OAST=Intrusive；Shell/无限循环/Scope 外目标=拒绝发布；声明风险不得低于计算风险
- [ ] **Step 3: 实现** - RiskAnalyzer.analyze(case) -> computed_risk；静态扫描 YAML/Python；声明 risk < computed -> 阻止发布；Shell/无限循环 -> 拒绝
- [ ] **Step 5: 提交** `feat(risk): add static risk analyzer as publish gate`

## Task 9: PythonPluginSandbox（gVisor 或 seccomp，M2 锁定方案）

**Files:** `infrastructure/sandbox/python_sandbox.py`, `case_context.py`, `tests/infrastructure/test_python_sandbox.py`

- [ ] **Step 1: 测试** - CaseContext SDK 提供 scoped_http/scoped_tcp/credential_ref/temp_fs/oast/emit_observation；禁止 subprocess/os.system/Docker Socket/宿主 FS/任意 Socket/DB 连接/动态 import；容器 read-only/non-root/cap-drop ALL/no-new-privileges/无 Host Network/无 Docker Socket
- [ ] **Step 3: 实现** - **M2 Step 1 锁定方案**：评估 gVisor（runsc runtime，最强隔离但需内核支持）vs seccomp profile（default deny + 白名单 syscall，轻量）-> 选 seccomp（Lite 友好，2C2G 可跑）；PythonPluginSandbox 用 Docker + seccomp profile + read-only + non-root + cap-drop ALL；CaseContext SDK 限制可用 API
- [ ] **Step 5: 提交** `feat(sandbox): add python plugin sandbox with seccomp`

## Task 10: CaseService（生命周期 + validate + dry_run）

**Files:** `application/cases.py`, `tests/application/test_case_service.py`

- [ ] **Step 1: 测试** - CaseService.create_draft/validate/publish；YAML Case 生命周期 DRAFT->VALIDATED->REVIEWED->SIGNED->PUBLISHED；Python Plugin DRAFT->STATIC_CHECKED->SANDBOX_TESTED->REVIEWED->SIGNED->PUBLISHED；validate 跑 RiskAnalyzer + schema；dry_run 在靶场跑；Agent 不能审核/签名/发布
- [ ] **Step 3: 实现** - CaseService 编排生命周期；validate 调 RiskAnalyzer + schema 校验 + FixtureRunner；dry_run 在 Juice Shop 跑；签名 Ed25519；发布进 CaseRegistry
- [ ] **Step 5: 提交** `feat(cases): add case service lifecycle`

## Task 11: FixtureRunner（5 类 fixture 校验）

**Files:** `application/fixture_runner.py`, `tests/application/test_fixture_runner.py`

- [ ] **Step 1: 测试** - 每 Case 5 类 fixture（positive/negative/timeout/scope_deny/malformed）+ 脱敏；Intrusive Case 还须靶场/前后状态/清理/最大影响；fixture 全过才允许发布
- [ ] **Step 3: 实现** - FixtureRunner.run(case) -> FixtureResult；5 类 fixture 执行；positive 应报/negative 不应报/timeout 处理/scope_deny 拒绝/malformed 不崩；Intrusive 额外校验
- [ ] **Step 5: 提交** `feat(fixture): add fixture runner with 5 class validation`

## Task 12: Evidence 三层 + RedactionEngine

**Files:** `domain/evidence/models.py`, `application/evidence.py`, `infrastructure/evidence_store/local_cas.py`, `redaction.py`, `tests/domain/test_evidence.py`

- [ ] **Step 1: 测试** - Evidence RAW/REDACTED/SUMMARY 三层；内容寻址 sha256；脱敏生成新对象不覆盖 RAW；RedactionEngine regex（Secret/PII/内网 IP）；区分我方 secret vs 目标 secret；Redacted 独立签名；误报率指标
- [ ] **Step 3: 实现** - Evidence dataclass（layer/sha256/storage_uri/redaction_status）；LocalCAS `sha256/<prefix>/<digest>`；RedactionEngine regex 库（API key/JWT/AWS key/私钥/邮箱/身份证/手机号/内网 IP）；两类 secret 标记；auto+人审；Report 渲染层再过 Redaction（M9）
- [ ] **Step 5: 提交** `feat(evidence): add three layer evidence with redaction`

## Task 13: M2 质量门 + 文档

- [ ] ruff/mypy + pytest 全绿 + oracle 靶场集回归绿
- [ ] `docs/architecture/verification.md` + `docs/cases/yaml-dsl.md`
- [ ] 提交 `docs(m2): close verification and case engine baseline`

---

## M2 最终验收

- [ ] OracleEngine 采纳 ptai + VerificationMethodRegistry 策展
- [ ] N/N 复证生效，LLM 永不标记 Confirmed
- [ ] oracle ground-truth 靶场集（Juice Shop/crAPI/vulhub）回归通过
- [ ] 自托管 Interactsh OOB
- [ ] YAML Case Nuclei 兼容+扩展，DSL AST 不用 eval
- [ ] Python 沙箱 seccomp 隔离，CaseContext SDK 限制
- [ ] RiskAnalyzer 发布门禁
- [ ] CaseService 生命周期，Agent 不能发布
- [ ] FixtureRunner 5 类 fixture
- [ ] Evidence 三层 + RedactionEngine
- [ ] ruff/mypy/pytest 全绿

## 下一步

M2 通过后，写 M3 模型驱动逻辑测试详细计划。M3 依赖 M2 的 CaseRegistry + CaseEngine + 验证流水线。
