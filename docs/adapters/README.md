# Adapter Pack（四域工具适配层）

> 状态：M1 基线——4 域 17 个 Adapter 全部落地，输出归一化为 `Observation`，每个 Adapter 通过 5 类 fixture 契约测试。
> 设计来源：`sepcs/2026-07-25-catalog-driven-agent-workbench-design.md` §8。

每个 Tool Adapter（资产测绘 / Web-API / 网络主机 / 云容器）满足同一契约面（`domain/adapters/contracts.py`），把异构工具输出归一化为 Faraday 风格的 `Observation` 记录。

## 四域清单

| 域 | CoverageDomain | Adapter | 上游工具 | 风险类 | 许可证 |
|---|---|---|---|---|---|
| 资产测绘 | `asset` | subfinder | projectdiscovery/subfinder | PASSIVE | MIT |
| | | httpx | projectdiscovery/httpx | PASSIVE | MIT |
| | | naabu | projectdiscovery/naabu | ACTIVE | MIT |
| | | katana | projectdiscovery/katana | ACTIVE | MIT |
| | | fingerprinthub | fingerprinthub | PASSIVE | MIT |
| Web-API | `web` | nuclei | projectdiscovery/nuclei | ACTIVE | MIT |
| | | dalfox | hahwul/dalfox | ACTIVE | MIT |
| | | restler | microsoft/restler | ACTIVE | MIT |
| | | schemathesis | schemathesis/schemathesis | ACTIVE | MIT |
| | | zap | zaproxy/zaproxy | INTRUSIVE | Apache-2.0 |
| 网络主机 | `network` | nmap | nmap | ACTIVE | GPL（独立进程） |
| | | nuclei_tcp | projectdiscovery/nuclei (TCP) | ACTIVE | MIT |
| 云容器 | `cloud` | prowler | prowler-cloud/prowler | PASSIVE | Apache-2.0 |
| | | trivy | aquasecurity/trivy | PASSIVE | Apache-2.0 |
| | | kube_bench | aquasecurity/kube-bench | PASSIVE | Apache-2.0 |
| | | checkov | bridgecrewio/checkov | PASSIVE | MIT |
| | | scoutsuite | nccgroup/ScoutSuite | PASSIVE | GPL-2.0（独立进程） |

> **GPL 工具**（nmap NSE、ScoutSuite）以**独立子进程**调用，不内嵌为库——manifest 在 `permissions` 中携带 `independent_process` 标记，执行层据此路由到进程隔离，保持聚合层许可证干净。

## Manifest 契约（§8.1）

每个 Adapter 暴露 `manifest() -> AdapterManifest` 与 `parse(*, stdout, source, artifacts) -> tuple[Observation, ...]`。

`AdapterManifest` 声明：
- `id` / `version` / `adapter_api_version`
- `license`（许可证，GPL 工具标 GPL-2 族）
- `upstream`（`name` / `url` / `version` / `digest`——上游制品钉死 digest，绝不用浮动 tag）
- `risk_class`（`RiskClass`：PASSIVE/LOW/ACTIVE/INTRUSIVE/DESTRUCTIVE）
- `coverage_domain`（`CoverageDomain` 元组，至少一个）
- `input_schema` / `output_schema`
- `network_policy`（默认 `scoped-egress`）
- `parser`（解析器入口字符串）
- `fixtures`（5 类 fixture 路径）
- `permissions`（能力 + 可选 `independent_process` 标记）
- `digest`（manifest 内容的规范化摘要，构造时计算，可验证完整性）

`parse` 必须是 stdlib-only（仅 `json` 等标准库），且**任何解析失败都返回空元组**——畸形工具流绝不能拖垮 runner。

## Observation 归一化（§8.3）

低信任、可复现、带来源归属的事实记录：
- `cwe` / `cve` / `owasp` 元组喂给 CoverageMatrix（覆盖判定的输入）
- `confidence` 是 [0.0, 1.0] 概率
- `severity`（`Severity` 枚举）与 `coverage_domain`（`CoverageDomain` 枚举）——下游绝不解析自由文本
- `raw` 保留原始工具输出，供审计/重放

## 5 类 Fixture 契约测试

每个 Adapter 在 `tests/adapter_contract/` 下通过 5 类 fixture（真实工具输出的样本，非真实执行——真实工具执行是 M5 E2E）：

| Fixture | 含义 | 断言 |
|---|---|---|
| `positive` | 良构工具输出 | ≥1 Observation，`coverage_domain` 正确，`asset_identity` 已填充，CWE/CVE/OWASP（如适用）已提取 |
| `negative` | 空但良构输出 | 0 Observation |
| `timeout` | 工具超时（exit_code != 0） | AdapterRunner 报非 COMPLETED 状态 + errors |
| `scope_deny` | 越界目标 | M0 PolicyEngine / cloud scope gate 在容器执行**之前**拦截（ScopeDeniedError） |
| `malformed` | 损坏输出 | parser 返回 0 Observation，不抛异常 |

## 执行与 Scope 强制（AdapterRunner，§8.1/§8.4）

`infrastructure/adapters/base.py` 的 `AdapterRunner` 是唯一集成点，按序强制三条不变式：

1. **Scope 门先行**：对每个 target 走 scope 校验，拒绝即抛 `ScopeDeniedError`，**绝不执行容器**。
   - 网络目标（URL/IP/domain）走 M0 `PolicyEngine.evaluate`（scope + port + risk + capability）。
   - 云目标（`provider:account_id`，manifest 覆盖 cloud 域）走 `ScopeSnapshot.includes_cloud_account`（`cloud_accounts` 集合，Deny 优先），跳过 URL/port 校验但保留 Destructive->scope->risk->capability 决策序。
2. **钉死镜像执行**：用 `upstream.digest`（非浮动 tag）+ §8.4 安全标志（`--user=nonroot --cap-drop=ALL --read-only --network=scoped-egress`）。
3. **产物归一化**：每个产物 sha256 入 CAS，parser 解析 stdout 产出 `Observation`。

`ContainerExecutor` 是 Protocol——测试注入 mock，生产 Docker 实现（M5）可无缝替换。
