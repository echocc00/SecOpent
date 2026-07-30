# T5 §3.2 端到端编排 - 精准执行计划

> **日期**：2026-07-29
> **写给**：开发模型
> **前置**：T1-T4 已验收通过（938 passed / ruff / mypy 217 / 工作树 @ 570b436）
> **本文档基于实测代码**：PlanStep 真实字段、StepRunner 真实缺口、FindingCorrelator/CoverageService 真实签名
> **性质**：v1.1-stable 硬门禁，必停验收闸

---

## 0. T5 真实工作量（非纯写测试）

**核查发现**：`StepRunner` 是 Protocol（`orchestrator.py:50`），**无具体实现**。现有 `test_real_scans.py` 不用 Orchestrator，是单适配器直跑。

**T5 = 两件事**：
1. **补 StepRunner 具体实现**（Planner 的 PlanStep -> adapter docker 执行 -> Observations -> StepResult 的胶水）-- 这是缺失的集成层
2. **写 3 场景 e2e_real 测试**（Web/API/云，经 Orchestrator.run_to_completion 全链路）

**预期暴露集成 bug**，预留 3-4 天修。

---

## 1. 真实接口（实测，非假设）

### PlanStep（`domain/assessments/models.py:28`）
```python
@dataclass(frozen=True, slots=True)
class PlanStep:
    key: str                          # 唯一步骤 id
    runner: str                       # 适配器名："nuclei"/"dalfox"/"nmap"...
    risk: RiskClass
    parameters: dict[str, object]     # 适配器参数：target/templates/ports...
    dependencies: tuple[str, ...]     # 上游 step key
```

### Orchestrator（`application/orchestrator.py:52`）
```python
class StepRunner(Protocol):
    def run(self, step: PlanStep) -> StepResult: ...

class Orchestrator:
    def __init__(self, jobs: JobService, runner: StepRunner, *, max_workers: int = 1)
    def execute_ready(self, *, owner: str, now: datetime) -> tuple[Job, ...]
    def run_to_completion(self, *, owner: str, now: datetime, max_rounds: int = 100) -> None
```

### 已存在的服务（直接用）
- `FindingCorrelator.correlate(observations: Iterable[Observation]) -> tuple[Finding]`（`application/finding_correlation.py:34`）
- `CoverageService.compute(...)`（`application/coverage.py:26`）
- `Planner.generate(...)`（`application/planner.py:47`）
- `RescanVerifier`（`infrastructure/oracle/rescan_verifier.py`，现有 test_real_scans 已用）
- `SubprocessExecutor(max_workers=N).run_many(...)`（T4 已加并发）
- `ReportRenderer.render(data, report_id=...)`（`application/report_renderer.py:66`）

---

## 2. StepRunner 具体实现（T5 第一块，新建）

**文件**：`src/secopent/infrastructure/adapters/step_runner.py`

```python
from __future__ import annotations
from dataclasses import dataclass
from ...application.orchestrator import StepRunner
from ...domain.assessments.models import PlanStep, StepResult
from ...domain.adapters.contracts import Observation
from .subprocess_executor import SubprocessExecutor
from .adapter_registry import ADAPTERS  # 现有适配器注册表

@dataclass(frozen=True, slots=True)
class AdapterStepRunner(StepRunner):
    """PlanStep -> adapter docker 执行 -> Observations -> StepResult.

    这是 Planner 与 adapter 执行层之间的胶水：读 step.runner 选适配器，
    用 step.parameters 构造调用，经 SubprocessExecutor 跑真实容器，
    parse 输出为 Observations，打包成 StepResult。
    """
    executor: SubprocessExecutor

    def run(self, step: PlanStep) -> StepResult:
        adapter = ADAPTERS.get(step.runner)
        if adapter is None:
            raise ValueError(f"unknown adapter: {step.runner!r}")
        # 1. 构造 adapter invocation（target/templates 等从 step.parameters）
        invocation = adapter.build_invocation(step.parameters)
        # 2. 真实 docker 执行（digest-pinned，安全标志）
        result = self.executor.run(invocation)
        # 3. parse 输出 -> Observations
        observations = adapter.parse(result.stdout, step=step.key)
        # 4. 打包 StepResult（含 result_digest 供审计/幂等）
        return StepResult(
            step_key=step.key,
            status=_classify(result, observations),
            observations=tuple(observations),
            result_digest=canonical_digest([o.to_dict() for o in observations]),
        )
```

**关键设计点**：
- `step.runner` -> `ADAPTERS` 注册表查适配器（复用现有 `image_catalog` + adapter 实现）
- `step.parameters` -> `adapter.build_invocation()` 把参数转成 docker 命令
- 输出 parse 复用各 adapter 现有 parser（M1 Task 9-12 已实现）
- `result_digest` 供审计链 + 幂等校验

**TDD**：先写 `tests/infrastructure/test_step_runner.py`（mock executor，验 adapter 选择/参数传递/parse/digest），再实现。

---

## 3. 三场景测试（T5 第二块）

**文件**：`tests/e2e_real/test_orchestration.py`（新建，`@pytest.mark.e2e_real`）

### 场景 1：Web 黑盒 Juice Shop（全链路）
```python
@pytest.mark.e2e_real
def test_full_web_pentest_juice_shop(require_target, tmp_path):
    url = require_target("juice_shop")
    now = utc_now()

    # 1. scope 冻结
    snapshot = ScopeService(repo).freeze(ScopeDraft(include=[url], ports=[3000]))

    # 2. catalog（默认已 seed）+ planner 生成 plan
    catalog = catalog_repo.latest_catalog()
    assert catalog is not None  # §3.1 默认种子保证
    plan = Planner(...).generate(snapshot, catalog=catalog)
    assert plan.steps, "plan 必须非空"
    assert any(s.runner == "nuclei" for s in plan.steps)

    # 3. 存 plan + 建 jobs（每个 step 一个 Job）
    assessment_repo.save_plan(plan)
    for step in plan.steps:
        jobs.add(Job.from_step(step, assessment_id=assessment.id))

    # 4. Orchestrator 跑到完成（真实 adapter 容器，T4 并发可用）
    runner = AdapterStepRunner(SubprocessExecutor(max_workers=3))
    Orchestrator(jobs, runner, max_workers=3).run_to_completion(owner="e2e", now=now)

    # 5. 结果聚合 -> findings
    all_obs = [o for j in jobs.all() for o in j.result.observations]
    findings = FindingCorrelator().correlate(all_obs)
    assert findings, "Juice Shop 必有 finding"

    # 6. oracle N/N 复现
    verifier = RescanVerifier(runner, scan_kwargs={...})
    for f in findings:
        f = replace(f, oracle_verdict=verifier.verify(f))
    confirmed = [f for f in findings if f.oracle_verdict == VerificationStatus.CONFIRMED]
    assert confirmed, "必有 CONFIRMED（SQLi/XSS）"

    # 7. 覆盖率
    coverage = CoverageService(...).compute(plan, findings)
    assert coverage.rate > 0.2

    # 8. 报告 + 三层证据 + 审计链
    report = ReportRenderer(...).render(
        ReportData(findings=findings, coverage_rate=coverage.rate), report_id=...)
    assert report.sections
    assert all(f.evidence.raw_uri and f.evidence.redacted_uri for f in confirmed)
    assert AuditChain(repo).verify().valid
```

### 场景 2：API 测试 httpbin（Schemathesis 集成）
```python
@pytest.mark.e2e_real
def test_full_api_pentest_httpbin(require_target, tmp_path):
    url = require_target("httpbin")
    # 同结构，plan 含 schemathesis step（OpenAPI 驱动）
    # 断言：5 类状态码突变 finding + schema 不一致
```

### 场景 3：云资产本地 docker.sock
```python
@pytest.mark.e2e_real
def test_full_cloud_pentest_docker_socket():
    # scope = 本地 docker.sock
    # plan 含云适配器（trivy/cis 长镜像扫描等）
    # 断言：容器逃逸/权限 finding
```

---

## 4. 预期集成 bug（预留 3-4 天修）

首次真实跑必然暴露，逐个修：

| # | 预期 bug | 位置 | 修法 |
|---|---|---|---|
| 1 | `Planner.generate` 的 step.parameters 与 adapter.build_invocation 参数名不一致 | planner.py vs adapter | 对齐参数契约（target vs url 等） |
| 2 | `Job.from_step` 不存在或字段不全 | assessments/models.py | 补 from_step 工厂 |
| 3 | Orchestrator 执行后 observations 未存回 Job | orchestrator.py | StepResult 持久化到 Job |
| 4 | FindingCorrelator 输入 Observation 字段与 adapter parse 输出不匹配 | finding_correlation.py vs adapter parser | 对齐 Observation schema |
| 5 | RescanVerifier 需 StepRunner 但签名要 scan_kwargs | rescan_verifier.py | 适配 AdapterStepRunner |
| 6 | evidence 三层 URI 实际未落盘 | evidence_store | 补 RAW/REDACTED/SUMMARY 写盘 |
| 7 | CoverageService.compute 签名与调用不匹配 | coverage.py | 对齐 plan+findings 入参 |
| 8 | 审计链跨 service 写入顺序导致 hash 断 | audit_chain.py | 单 txn 写或补 previous_hash 传递 |

**修 bug 原则**：每个 bug 写一个回归测试再修，不直接改。

---

## 5. 执行步骤（今天怎么开始）

```bash
# 1. 起靶场
cd /f/claudepc/SecOpent
docker compose -f scripts/provision/docker-compose.targets.yml up -d
curl -s http://localhost:3000 | head   # 确认 Juice Shop
curl -s http://localhost:8080/get      # 确认 httpbin

# 2. 先做 StepRunner（TDD）
#    写 tests/infrastructure/test_step_runner.py（mock executor）-> RED
#    实现 AdapterStepRunner -> GREEN

# 3. 再写场景 1（Juice Shop），跑 e2e_real，逐个修 §4 的 bug
py -3.12 -m pytest -m e2e_real tests/e2e_real/test_orchestration.py -x -v

# 4. 场景 2/3 重复

# 5. 质量门
py -3.12 -m pytest -q          # 938+ 无回归
py -3.12 -m ruff check .
py -3.12 -m mypy src/secopent  # 217+ 文件
```

---

## 6. 验收（必停，T5 完成找我）

- [ ] `AdapterStepRunner` 实现 + 单元测试绿
- [ ] 3 场景 `pytest -m e2e_real` 全绿（需 Docker 靶标 up）
- [ ] 每场景留 evidence 三层 + 审计链可校验
- [ ] §4 集成 bug 逐个有回归测试
- [ ] 全套 938+ 无回归 + ruff/mypy clean
- [ ] commit `feat(e2e): real orchestration end-to-end + AdapterStepRunner (T5 §3.2)`

**T5 完成后停下找我验收**，我验 3 场景 + bug 修复后才继续 T6。

---

## 7. T5 之后的任务（提醒，勿现在做）

| # | 任务 | 工期 | 何时 |
|---|---|---|---|
| T6 | P2-F crAPI/vulhub 四域真实扫 | 1-2w | T5 后，共享靶场（加 crAPI 到 compose） |
| T7 | ① CI 加固 | 2-3d | 可与 T5 并行 |
| T8 | ⑦ 备份恢复 | 2-3d | 可并行 |
| T9 | ② 发布流程 | 2d | 可并行 |
| T10 | tag v1.1-stable | - | T5-T9 全过后 |
| T11 | P2-G nftables | 1-2w | Linux CI |
| §3.6 残留 | Monaco 671KB -> <350KB | 1d | 用 CDN+SRI 或 CodeMirror 评估 |

**§3.6 Monaco 残留**（实测 `editor.api` = 671.51 KB gzip，目标 <350KB）：选项 A 用 CDN+SRI（但离线合规受影响）；选项 B 评估换 CodeMirror 6（~150KB，但需重写 YamlEditor）；选项 C 接受（懒加载仅 CaseStudio 付）。**建议 v1.1-stable 前选 A 或 C，B 留 P4**。

---

## 8. 未跟踪文档

3 份规划文档 untracked（`v1.1-stable-final-and-p4-plan.md` / `cross-cutting-concerns-plan.md` / `dev-handoff-master.md`）。建议你做一个 `docs: archive T5/T6/cross-cutting planning docs` commit 归档，便于后续追溯。

---

*T5 是硬门禁。先补 AdapterStepRunner，再 3 场景，预留修 bug。完成后停下找我。*
