# YAML Case DSL（用例引擎）

> 状态：M2 基线。Case domain + YAML schema（Nuclei 兼容+扩展）、no-eval AST 断言求值、DSL 解释器（硬上限+安全拒绝）、RiskAnalyzer 发布门禁、CaseService 生命周期、FixtureRunner、PythonPluginSandbox（seccomp）。
> 设计来源：`sepcs/2026-07-25-catalog-driven-agent-workbench-design.md` §11；ADR-006（Nuclei YAML 基础+扩展，非自研 DSL）。

## Nuclei 兼容 + 三类验证扩展（§11.2）

以 Nuclei YAML 为基础格式（事实标准、10k+ 现成模板可复用），扩展三类钩子：

1. **`{{canary_token}}` 占位**：探针中由 oracle 的 canary token 替换。
2. **`verification` 块**：关联 VerificationMethodRegistry + 复现次数（`method` / `reproduce`）。
3. **`classification` 块**：`cwe` / `cve` / `owasp`，喂给 CoverageMatrix。

```yaml
id: sqli-time-based
version: "1.0.0"
author: analyst
schema: nuclei+secopent/1
risk: active                # 声明的动作风险（不得低于计算风险）
target_type: http
origin: manual              # manual / model_generated / community
classification: { cwe: [CWE-89], owasp: [A03:2021] }
evidence_req: [raw, redacted]
verification: { method: sqli, reproduce: 5 }
steps:
  - id: req1
    action: http.request
    spec: { method: GET, path: "/?id={{canary_token}}" }
assertions:
  - id: a1
    expression: "contains(body, canary_token)"
```

`domain/cases/yaml_schema.py::case_from_mapping` 做纯 `dict -> CaseDefinition` 校验（domain 框架无关）；YAML 字符串→dict 由 `infrastructure/case_engine/yaml_parser.py` 用 `yaml.safe_load` 完成（绝不 `yaml.load`，不能实例化任意 Python 对象）。

## DSL actions + 约束（§11.3）

支持：`dns.resolve, tcp.connect, tls.inspect, http.request, http.compare, oast.allocate, oast.wait, extract.regex/jsonpath/xpath, transform.base64/urlencode/hash, compare.text/numeric/timing, condition, foreach, retry, wait`。

约束（`infrastructure/case_engine/interpreter.py` 强制）：
- `foreach/retry/wait` **必须有硬上限**（cap：foreach≤100，retry≤10，wait≤300s）。
- **禁止** 递归 / 无限循环 / Shell / 动态 import / 任意文件路径 / 动态创建 Scope 外目标 → `InterpreterError` 拒绝运行。
- 断言用**内部 AST，不用 Python eval**。

## 断言：no-eval AST 求值器（§11.3）

`ast_evaluator.py` 用标准库 `ast` 解析断言表达式，只解释白名单节点与函数；从不调用 `eval`/`exec`，拒绝属性访问/下标/lambda/任意调用——断言字符串无法逃逸到任意代码执行。

- 支持：字面量、list/tuple（用于 `in`）、上下文变量名、比较 `== != < <= > >= in not in`（可链式）、布尔 `and/or/not`、一元负号。
- 白名单函数：`contains, len, matches, starts_with, ends_with, equals, lower, upper`。

## 风险静态分析（§11.6，发布门禁）

`application/risk_analyzer.py` 静态扫描步骤计算动作风险：

| 模式 | 计算风险 |
|---|---|
| GET/HEAD | Low |
| 全面扫描/爬虫/有界 foreach | Active |
| 凭据/上传/时间差/OAST | Intrusive |
| Shell/无限循环/Scope 外目标 | **拒绝发布** |

**声明风险不得低于计算风险**（可声明更高，保守允许）。不达标 `RiskAnalyzer.enforce_publish` 阻止发布。

## Python 插件沙箱（§11.4，seccomp）

`infrastructure/sandbox/python_sandbox.py`：插件运行前**静态扫描**，拒绝 forbidden import（subprocess/os/socket/docker/ctypes/importlib/shutil/sys）与 forbidden call（eval/exec/compile/__import__/open/getattr/...）。隔离用 **seccomp**（M2 锁定，比 gVisor 轻，2C2G Lite 可跑）+ 容器 `read-only / non-root / cap-drop ALL / no-new-privileges / 无 Host Network / 无 Docker Socket`。

插件只能通过 **CaseContext SDK** 获取声明式 Capability：`scoped_http / scoped_tcp / credential_ref / temp_fs / oast / emit_observation`。`credential_ref` 返回引用句柄，**绝不返回原始 secret**。Docker/seccomp 运行时在 M5；M2 用注入的 `SandboxRuntime` mock。

## 生命周期（§11.5/§11.8）

```
YAML Case:  DRAFT -> VALIDATED -> REVIEWED -> SIGNED -> PUBLISHED  (-> DISABLED / DEPRECATED)
```

`application/cases.py::CaseService` 编排：`validate` 跑 RiskAnalyzer 门禁；`review/sign/publish` 为**人审动作**——**Agent 可创建/校验，但禁止审核/签名/发布**（LLM边界）。签名独立。

## Fixture 要求（§11.7）

`application/fixture_runner.py`：每 Case 必备 5 类 fixture——positive（应报）/ negative（不应报）/ timeout / scope_deny / malformed（后三者优雅处理：不报且不崩）。**Intrusive Case 还须** range（靶场）/ before_after（前后状态）/ cleanup（清理）/ max_impact（最大影响）。5 类全过才允许发布。
