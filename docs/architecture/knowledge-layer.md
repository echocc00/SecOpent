# 知识层（Knowledge Layer）

> 状态：M1 基线（TestCatalog / CoverageMatrix / Intel / Adapter 契约 + 四域 Adapter Pack + UpdateManager + HealthMonitor 已落地）。
> 设计来源：`sepcs/2026-07-25-catalog-driven-agent-workbench-design.md` §7。

知识层是 SecOpent 的产品护城河，回答「测什么 / 怎么测 / 验什么」。它与 LLM 无关——LLM 只提议，确定性层（TestCatalog / CoverageMatrix / OracleEngine）裁决（LLM边界）。

## 四子层结构

```
知识层
+-- 外部聚合子层（Aggregation）——自动同步，产品不著述只搬运
|   +- 引擎模板镜象：nuclei-templates / nmap NSE / Prowler / ScoutSuite / Trivy-DB / kube-bench / checkov
|   +- 情报 feeds：OSV / CISA KEV / EPSS / NVD(代理) / CWE / GitHub Advisory
+-- 策展子层（Curation）——产品 IP，人工+半自动维护
|   +- TestCatalog（资产类型 -> 必修测试类映射）
|   +- CoverageMatrix（OWASP WSTG/Top10/CIS/PTES 条目 -> 测试类映射 + 覆盖率报告）
|   +- Tool Registry（工具 manifest/schema/parser）
|   +- LogicTestGenerator 策略库（测试生成算法）
|   +- VerificationMethodRegistry（漏洞类型 -> 验证方法）
+-- 社区/用户子层（Community）
|   +- Custom POC Registry（签名、审核、版本化）
|   +- AppModel Registry（per-app，用户签名）
+-- 参考框架子层（Reference）——缓慢更新
    +- OWASP WSTG/Top10、CIS Benchmarks、PTES、NIST 800-115、CWE
```

**关键洞察**：产品不著述模板（那是上游 nuclei/Prowler 团队的工作），产品做**聚合 + 映射 + 覆盖量化**。单兵策展负担从「著述一万条规则」降到「维护映射表」。

## 来源全景

| Registry | 来源 | 获取 | 频率 | 许可证 | 谁著述 |
|---|---|---|---|---|---|
| nuclei-templates | projectdiscovery/nuclei-templates | git pull | 每日 | MIT | 上游 PD |
| nmap NSE | nmap 发行版 | bundled | 跟版本 | GPL（独立进程） | 上游 |
| Prowler | prowler-cloud/prowler | git pull | 每周 | Apache-2.0 | 上游 |
| ScoutSuite | nccgroup/ScoutSuite | git pull | 每周 | GPL-2（独立进程） | 上游 |
| Trivy-DB | aquasecurity/trivy-db | git/OCI | 每日 | Apache-2.0 | 上游 |
| kube-bench / checkov | aquasec / bridgecrewio | git pull | 每月/每周 | Apache/MIT | 上游 |
| OSV | api.osv.dev | REST 增量 | 6h | CC-BY-4.0 | 上游 |
| CISA KEV | cisa.gov JSON | 下载 | 6h | 公共 | CISA |
| EPSS | first.org | CSV | 每日 | CC-BY-SA-4.0 | FIRST |
| NVD | nvd.nist.gov（国内代理） | REST 增量 | 6-12h | 公共 | NIST |
| CWE / GHSA | mitre / github | 下载/git | 每月/每日 | 公共/CC-BY | 上游 |
| TestCatalog / CoverageMatrix 映射 | 产品策展 | 内部 | 月评审 | 产品 IP | 产品+社区 |

开源分层（决策 O4=B）：**聚合层 + CoverageMatrix** MIT 开源；**TestCatalog / AppModel / OracleEngine** 为产品 IP。

## 维护更新机制

- **自动同步（聚合子层）**：`UpdateManager` 按各源频率增量拉取；git 源记 commit SHA，REST 源用 `last_modified` 游标；流程为 入 Staging DB -> 签名校验（Ed25519）-> schema/兼容检查 -> 变更预览 -> 原子激活 -> 保留旧快照可回滚。落地于 `application/updates.py`。
- **策展维护（策展子层）**：TestCatalog 评估新 nuclei tag 是否纳入必修；CoverageMatrix 在 OWASP WSTG 新版时重映射；Tool Registry 跟工具版本。策展变更走签名 bundle 发布，社区可 PR。
- **质量保障**：每个 TestCatalog 映射条目要求 ≥1 fixture；CoverageMatrix 覆盖率作为发布门禁；策展变更需通过契约测试；社区贡献需审核+签名。

## 退化门禁（选项 D：0 容忍 + override-with-reason）

由 `KnowledgeHealthMonitor`（`application/health.py`）执行，作用于策展子层新版本发布：**新版覆盖率 < 旧版 -> 阻止发布**（或带理由 override）。

| 检测 | 告警条件 |
|---|---|
| 源停更 | nuclei-templates 超 7 天无新 commit |
| 策展滞后 | nuclei 新增 100 tag 但 TestCatalog 未映射 |
| 覆盖率退化 | 新版覆盖率 < 旧版 |
| 源失效 | OSV API 不可达 -> 降级缓存 + 告警 |
| 签名失效 | bundle 签名校验失败 |

**触发场景**：上游模板移除、上游许可证变更、工具停更、映射错误、误报清洗、OWASP 框架升级、产品主动收窄。历史评估不受影响（钉旧快照）。

## 与覆盖门禁的关系

- **覆盖率退化门禁**（本节）：作用于**策展层发布**——catalog 新版本不能比旧版本覆盖更少。
- **执行覆盖门禁**（`CoverageService`，`application/coverage.py`）：作用于**单个 Assessment**——0 未执行必修测试类才能结题。一个必修测试类被「覆盖」当且仅当某条 Observation 的 CWE/OWASP 与其实录 curated CWE/OWASP 相交（确定性集合判定，无 LLM）。

两者共同保证「测什么」的知识既不在发布时退化、也不在执行时被跳过。
