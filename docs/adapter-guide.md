# Adapter 开发指南（Adapter Guide）

> 面向开发者：为 SecOpent 新增一个工具适配器（adapter）。读完应能独立交付一个新 adapter 并通过契约测试。
> 状态：P3 §3.7。设计原理见 `docs/adapters/README.md`（四域清单 + Observation 归一化）与 `docs/architecture/subprocess-executor.md`（执行层）。

Adapter 把一个安全工具（nuclei / dalfox / nmap / prowler …）封装成统一契约：**声明式 manifest** + **stdlib-only parser**，输出归一化为 Faraday 风格 `Observation`。现有 17 个 adapter 见 `docs/adapters/README.md`。

## 1. 契约面（两件事）

每个 adapter 模块（`src/secopent/integrations/adapters/<name>/__init__.py`）暴露两个函数：

```python
def manifest() -> AdapterManifest: ...
def parse(*, stdout: str, source: AdapterSource, artifacts: dict[str, bytes]) -> tuple[Observation, ...]: ...
```

- `manifest()`：声明身份、上游钉死、风险类、覆盖域、schema、网络策略、parser 入口、fixtures、permissions。
- `parse(...)`：把工具 stdout 归一化成 `Observation`。**必须 stdlib-only**（仅 `json`/`re` 等标准库），**任何解析失败都返回空元组 `()`**——畸形工具流绝不能拖垮 runner。可复用 `secopent.integrations.adapters._common.safe_jsonl_load`（JSONL 解析，失败返回 `[]`）。

契约数据类在 `domain/adapters/contracts.py`（frozen dataclass + StrEnum，无框架耦合）。

## 2. AdapterManifest 字段

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | str | ✓ | adapter 标识（如 `"nuclei"`） |
| `version` | str | ✓ | adapter 版本 |
| `adapter_api_version` | str | ✓ | 契约版本（当前 `"v1"`） |
| `license` | str | ✓ | 工具许可证（GPL 工具标 GPL-2 族） |
| `upstream` | AdapterUpstream | ✓ | `name`/`url`/`version`/`digest`——**上游制品钉死 digest，绝不用浮动 tag** |
| `risk_class` | RiskClass | ✓ | PASSIVE / LOW / ACTIVE / INTRUSIVE / DESTRUCTIVE |
| `coverage_domain` | tuple[CoverageDomain] | ✓ | 至少一个：asset / web / network / cloud |
| `input_schema` | str | ✓ | 输入 schema 引用（如 `schema://nuclei/input.json`） |
| `output_schema` | str | ✓ | 输出 schema 引用 |
| `network_policy` | str | ✓ | 默认 `"scoped-egress"` |
| `parser` | str | ✓ | 解析器入口字符串（如 `"secopent_adapters.nuclei:parse"`） |
| `fixtures` | tuple[str] | | 5 类 fixture 逻辑路径 |
| `permissions` | tuple[str] | | 能力（首个即 scope 门用的 capability）；GPL 独立进程标 `independent_process` |
| `digest` | str | 自动 | manifest 内容的规范化摘要（构造时算，**不含自身**），可验完整性 |

构造校验：上表 ✓ 字段非空，否则抛 `DomainValidationError`。参考实现：`integrations/adapters/nuclei/__init__.py` 的 `manifest()`。

## 3. 镜像钉死（digest-pin）

仓库**不含** per-adapter Dockerfile——adapter 跑的是上游公共镜像，在 `infrastructure/adapters/image_catalog.py` 的 `IMAGE_CATALOG` 中**按 sha256 digest 钉死**：

```python
IMAGE_CATALOG: dict[str, ImageRef] = {
    "nuclei": ImageRef("projectdiscovery/nuclei", "latest",
                       "sha256:e677842f..."),   # 钉死 digest
    ...
}
```

- `pull_spec(key)` 返回 `name@sha256:...`（有 digest 时）——`docker pull` 按 digest，**绝不拉浮动 `:latest`**。
- 升级工具 = 显式改 catalog + 重新 pin digest（`docker images --digests` 取），不是改 tag。
- 拉新镜像时先留空 digest（`""`），pull 后 `docker images --digests | grep <name>` 回填。
- manifest 的 `upstream.digest` 与 catalog 一致；AdapterRunner 用它作为执行镜像引用。
- 镜像经 China registry mirror（daemon.json）拉取，catalog 存 docker.io 规范名，mirror 透明。

## 4. Observation 归一化

低信任、可复现、带来源归属的事实记录。下游（CoverageMatrix / finding 关联）**只读枚举与元组，绝不解析自由文本**：

| 字段 | 必填 | 说明 |
|---|---|---|
| `external_id` | ✓ | 工具侧唯一 id（如 `nuclei:<template>:<host>:<idx>`） |
| `asset_identity` | ✓ | 目标资产（host/URL） |
| `source` | ✓ | AdapterSource（name/version/template_version） |
| `rule_id` / `rule_version` | ✓ | 规则 / 模板 id 与版本 |
| `coverage_domain` | ✓ | CoverageDomain 枚举 |
| `title` | ✓ | 人类可读标题 |
| `severity` | ✓ | Severity 枚举（info/low/medium/high/critical） |
| `confidence` | ✓ | [0.0, 1.0] 概率 |
| `cwe` / `cve` / `owasp` | | 元组，喂 CoverageMatrix（nuclei 由 template tag 映射） |
| `evidence_artifact_ids` | | 关联的 CAS 产物 id |
| `raw` | | 原始工具输出（审计 / 重放） |

parser 内应**去重**（如 nuclei 按 `template_id|host`），避免同目标重复 finding。

## 5. 执行与 scope 强制（AdapterRunner）

`infrastructure/adapters/base.py` 的 `AdapterRunner` 是唯一集成点，按序强制三条不变式：

1. **Scope 门先行**：每个 target 走 PolicyEngine（网络目标）或 cloud-account 成员检查（云目标），拒绝即抛 `ScopeDeniedError`，**绝不执行容器**。
2. **钉死镜像执行**：用 `upstream.digest` + 安全标志：
   `--user=nonroot --cap-drop=ALL --read-only --network=scoped-egress`
   默认资源限额：`cpu_quota=1.0 / memory_mb=512 / pids_limit=64 / no_new_privileges=true`。
3. **产物归一化**：每个产物 sha256 入 CAS，parser 解析 stdout 产出 `Observation`。

`ContainerExecutor` 是 Protocol——测试注入 mock（`RecordingExecutor`），生产用 `SubprocessContainerExecutor`（真实 `docker run`），runner 不变。`create_production_runner(...)` 装配生产 runner。

## 6. 五类 fixture 契约测试

每个 adapter 在 `tests/adapter_contract/test_<domain>_adapters.py`（按域分文件：asset / web_api / network_host / cloud_container）过 5 类 fixture（**样本工具输出，非真实执行**——真实容器执行是 E2E）：

| Fixture | 含义 | 断言 |
|---|---|---|
| `positive` | 良构输出 | ≥1 Observation，`coverage_domain` 正确，`asset_identity` 填充，CWE/CVE/OWASP（如适用）已提取 |
| `negative` | 空但良构输出 | 0 Observation |
| `timeout` | 工具超时（exit_code≠0） | runner 报非 COMPLETED + errors |
| `scope_deny` | 越界目标 | PolicyEngine 在容器执行**之前**拦截（`ScopeDeniedError`） |
| `malformed` | 损坏输出 | parser 返回 0 Observation，**不抛异常** |

测试用 `RecordingExecutor`（mock ContainerExecutor，记录 image_digest/command/mounts/flags）+ `FakeCASStore`；fixture 数据内联在测试文件。manifest 测试另断言 `coverage_domain` / upstream pin / risk_class 正确。

## 7. 新增 adapter 清单

1. **建模块** `src/secopent/integrations/adapters/<name>/__init__.py`，实现 `manifest()` + `parse()`（stdlib-only，失败返回 `()`）。
2. **钉镜像**：`infrastructure/adapters/image_catalog.py` 加 `IMAGE_CATALOG["<name>"] = ImageRef(...)`，pull 后回填 digest。
3. **归一化映射**：在 parser 里把工具输出映射到 `Observation`（severity 枚举、CWE/CVE/OWASP、去重）。
4. **契约测试**：在对应域 `tests/adapter_contract/test_<domain>_adapters.py` 加 5 类 fixture 用例 + manifest 断言。
5. **登记**：parser 入口字符串（`manifest().parser`）加入 runner 的 `parser_registry`；adapter 模块经 `secopent.integrations.adapters.<name>` 导入发现。
6. **GPL 工具**：以独立子进程调用，manifest `permissions` 带 `independent_process`（保持聚合层许可证干净）。
7. 跑 `python3 -m pytest tests/adapter_contract -q` + `ruff` + `mypy` 全绿。

## 8. 现有 17 adapter 参考

| 域 | Adapter | 工具 | 风险类 | 许可证 |
|---|---|---|---|---|
| asset | subfinder / httpx | projectdiscovery | PASSIVE | MIT |
| asset | naabu / katana | projectdiscovery | ACTIVE | MIT |
| asset | fingerprinthub | fingerprinthub | PASSIVE | MIT |
| web | nuclei / dalfox | projectdiscovery / hahwul | ACTIVE | MIT |
| web | restler / schemathesis | microsoft / schemathesis | ACTIVE | MIT |
| web | zap | zaproxy | INTRUSIVE | Apache-2.0 |
| network | nmap | nmap | ACTIVE | GPL（独立进程） |
| network | nuclei_tcp | projectdiscovery (TCP) | ACTIVE | MIT |
| cloud | prowler | prowler-cloud | PASSIVE | Apache-2.0 |
| cloud | trivy / kube_bench | aquasecurity | PASSIVE | Apache-2.0 |
| cloud | checkov | bridgecrewio | PASSIVE | MIT |
| cloud | scoutsuite | nccgroup | PASSIVE | GPL-2.0（独立进程） |

**最佳入门参考**：`nuclei`（JSONL 解析 + tag→CWE/OWASP 映射 + CVE 提取 + 去重），`_common.safe_jsonl_load` 复用。
