# 阶段 A 实现计划：让产品"能实际跑"

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** 把 V1 Beta（代码完成 + mock 验证）推进到 V1.0-usable（真实 Docker + 工具 + Interactsh + LLM，真实 E2E 三靶场绿，可做真实渗透测试）。这是从"代码"到"能跑"的关键跨越。

**Architecture:** 当前 AdapterRunner 只有 ContainerExecutor Protocol + mock。阶段 A 实现真实 SubprocessContainerExecutor（`docker run` + 安全 flags + digest 校验 + scoped egress），替换 mock，跑真实工具打真实靶场，修 mock-vs-真实偏差。ptai/Interactsh/LLM 从代码集成升级为真实部署。

**Tech Stack:** Docker Desktop, docker-compose, Python 3.12, subprocess, ptai (pentest-ai), Interactsh server, Ollama 或远程 LLM API, Playwright（Web 测试）, pytest（integration marks）。

**前置条件（必须先满足）：**
- 开发机装 Docker Desktop（当前环境无 Docker，**阶段 A 必须在 Docker 可用的机器上做**）
- 公网可达（拉镜像 + OSV/KEV/EPSS + LLM API）
- 若用远程 LLM，备好 API key

**DoD（阶段 A 完成定义）：**
- 真实 Docker + 17 工具镜像（digest 固定）部署可用
- SubprocessContainerExecutor 实现，真实工具在容器内跑
- 真实 E2E 三靶场（Juice Shop/crAPI/httpbin）绿，adapter 后端非 mock
- ptai 真实集成，oracle 在靶场集回归绿
- 自托管 Interactsh 部署，OOB 回调真实捕获
- Web Case Studio 浏览器实测 7 页可用
- LLM 真实接入，分级/脱敏/预算/降级验证
- mypy 全仓 clean（含 infrastructure）
- `git tag v1.0-usable`

**参考文档：**
- 主设计：`sepcs/2026-07-25-catalog-driven-agent-workbench-design.md` §8（Adapter）/§9（验证）/§12（安全）
- 交接指南：`sepcs/2026-07-25-handoff-implementation-guide.md` §4.1.1（cloud-scope）/§6（执行方式）
- M5 plan：`sepcs/2026-07-25-m5-security-beta-plan.md`（Scoped Egress / E2E）

---

## 0. 文件结构（新增/修改）

```text
src/secopent/
  infrastructure/
    adapters/
      subprocess_executor.py     # 新增：真实 docker run 执行器
      image_catalog.py           # 新增：17 工具镜像 digest 固定清单
    egress/
      scoped_egress_setup.py     # 新增/完善：netns + nftables + Docker network 创建
      interactsh_server.py       # 新增：自托管 Interactsh server 管理
  application/
    remote_model.py              # 修改：接真实 Ollama/远程 API backend
    oracle.py                    # 修改：ptai 真实调用（去 lazy import）
scripts/
  verify_env.py                  # 新增：环境验证脚本
  provision/
    docker-compose.targets.yml   # Juice Shop/crAPI/httpbin 靶场
    docker-compose.interactsh.yml# 自托管 Interactsh
    Dockerfile.scoped-egress     # scoped egress 代理容器
tests/
  integration/                   # 新增：真实集成测试（@pytest.mark.integration，无 Docker 跳过）
    test_subprocess_executor.py
    test_real_nuclei_scan.py
    test_real_nmap_scan.py
    test_real_prowler_scan.py
    test_ptai_oracle.py
    test_interactsh_oob.py
    test_real_llm_gateway.py
  e2e_real/                      # 新增：真实 E2E（替换 e2e/ 的 mock）
    test_juice_shop_real.py
    test_crapi_real.py
    test_httpbin_real.py
  web/                           # 新增：Playwright 浏览器测试
    test_case_studio_browser.py
docs/
  deployment/
    environment-setup.md         # 新增：环境配给指南
    troubleshooting.md           # 新增：常见问题
pyproject.toml                   # 加 pytest mark integration + playwright 依赖
```

---

## Task A1: 环境配给 + 验证脚本

**Files:** `scripts/verify_env.py`, `scripts/provision/*`, `docs/deployment/environment-setup.md`

- [ ] **Step 1: 装 Docker Desktop**（在开发机）
  - 下载 Docker Desktop for Windows，启用 WSL2 backend
  - 验证：`docker --version` && `docker run hello-world`
  - 若无法装 Docker（如受限环境），阶段 A 无法进行，先解决环境

- [ ] **Step 2: 镜像 digest 固定清单**
  - 写 `src/secopent/infrastructure/adapters/image_catalog.py`：17 adapter 对应的镜像 + digest
    ```python
    IMAGE_CATALOG = {
      "subfinder": ("projectdiscovery/subfinder:latest", "sha256:..."),
      "nuclei": ("projectdiscovery/nuclei:latest", "sha256:..."),
      "nmap": ("instrumentisto/nmap:latest", "sha256:..."),
      # ... 17 个
    }
    ```
  - 拉 17 镜像：`docker pull <image>@<digest>`（digest 固定，防供应链）
  - 验证：每镜像 `docker inspect` 确认 digest

- [ ] **Step 3: 靶场 docker-compose**
  - 写 `scripts/provision/docker-compose.targets.yml`：
    ```yaml
    services:
      juice-shop:
        image: bkimminich/juice-shop:latest
        ports: ["3000:3000"]
      crapi:
        image: ctfcrapi/crapi-web:latest
        ports: ["8080:8080", "8082:8082"]
      httpbin:
        image: kennethreitz/httpbin:latest
        ports: ["80:80"]
    ```
  - 启动：`docker compose -f scripts/provision/docker-compose.targets.yml up -d`
  - 验证：`curl http://localhost:3000`（Juice Shop）、`curl http://localhost:80`（httpbin）

- [ ] **Step 4: 自托管 Interactsh server**
  - 写 `scripts/provision/docker-compose.interactsh.yml`：
    ```yaml
    services:
      interactsh-server:
        image: projectdiscovery/interactsh-server:latest
        ports: ["53:53/udp", "80:80", "443:443", "2525:2525"]
        command: ["-domain", "oast.local", "-listen-ip", "0.0.0.0"]
    ```
  - 需要公网域名 NS 委托（或内网 DNS 指向 `oast.local`）
  - 内网测试：在开发机 `/etc/hosts` 加 `127.0.0.1 oast.local`，DNS 解析 `*.oast.local` 到 127.0.0.1
  - 启动 + 验证：`dig @127.0.0.1 test.oast.local` 应解析到 127.0.0.1

- [ ] **Step 5: LLM 后端**
  - 选项 a（本地，推荐 Lite）：装 Ollama，`ollama pull qwen2.5:7b`（或 llama3.2:8b）
  - 选项 b（远程）：备好 OpenAI/Claude/Gemini API key，存环境变量 `LLM_API_KEY`
  - 验证：`ollama run qwen2.5:7b "hello"` 或 `curl https://api.openai.com/v1/models -H "Authorization: Bearer $LLM_API_KEY"`

- [ ] **Step 6: 环境验证脚本**
  - 写 `scripts/verify_env.py`：检查 Docker、17 镜像、靶场可达、Interactsh、LLM
    ```python
    def verify_all() -> dict:
      checks = {
        "docker": check_docker(),
        "images": check_images(),  # 17 镜像 digest
        "targets": check_targets(),  # Juice Shop/crAPI/httpbin
        "interactsh": check_interactsh(),
        "llm": check_llm(),
      }
      return checks
    ```
  - 运行：`py -3.12 scripts/verify_env.py`，全部 pass

- [ ] **Step 7: 文档**
  - 写 `docs/deployment/environment-setup.md`：上述步骤 + 故障排查
  - 提交：`git add scripts/ src/secopent/infrastructure/adapters/image_catalog.py docs/deployment/ && git commit -m "feat(env): provision docker tools interactsh llm environment"`

**验收 A1：** `py -3.12 scripts/verify_env.py` 全 pass（Docker + 17 镜像 + 3 靶场 + Interactsh + LLM）

---

## Task A2: 真实 SubprocessContainerExecutor

**Files:** `src/secopent/infrastructure/adapters/subprocess_executor.py`, `tests/integration/test_subprocess_executor.py`

- [ ] **Step 1: 写集成测试**（`@pytest.mark.integration`，无 Docker 跳过）
  ```python
  # tests/integration/test_subprocess_executor.py
  @pytest.mark.integration
  def test_subprocess_executor_runs_nuclei(tmp_path):
      """真实跑 nuclei 扫 httpbin，验证 stdout + exit_code + artifacts。"""
      executor = SubprocessContainerExecutor()
      result = executor.run(
          image_digest="projectdiscovery/nuclei:latest@sha256:...",
          command=["-u", "http://host.docker.internal:80", "-jsonl"],
          mounts={"/out": str(tmp_path)},
          network_policy="scoped_http",
          resource_limits={"memory": "512m", "cpus": "0.5"},
      )
      assert result.exit_code == 0
      assert result.stdout  # nuclei JSONL 输出
      assert tmp_path / "nuclei-output.jsonl" exists or result.stdout

  @pytest.mark.integration
  def test_subprocess_executor_enforces_security_flags():
      """验证 docker run 带 --user nonroot --cap-drop ALL --read-only。"""
      executor = SubprocessContainerExecutor()
      # 用一个能打印 /proc/self/status 的镜像验证 nonroot
      result = executor.run(image_digest="alpine:latest@sha256:...", command=["id"], ...)
      assert "nonroot" in result.stdout or "uid=65532" in result.stdout

  @pytest.mark.integration
  def test_subprocess_executor_digest_mismatch_rejected():
      """digest 不匹配拒绝执行（防供应链）。"""
      executor = SubprocessContainerExecutor()
      with pytest.raises(ImageDigestMismatch):
          executor.run(image_digest="alpine:latest@sha256:wrong", ...)

  @pytest.mark.integration
  def test_subprocess_executor_scoped_egress_blocks_metadata():
      """云 metadata IP 169.254.169.254 被阻。"""
      executor = SubprocessContainerExecutor()
      result = executor.run(
          image_digest="alpine:latest", 
          command=["sh", "-c", "wget -T 2 http://169.254.169.254 || echo BLOCKED"],
          ...
      )
      assert "BLOCKED" in result.stdout
  ```

- [ ] **Step 2: RED** - `py -3.12 -m pytest -q tests/integration/test_subprocess_executor.py -m integration`（应 import fail 或 skip）

- [ ] **Step 3: 实现 SubprocessContainerExecutor**
  ```python
  # src/secopent/infrastructure/adapters/subprocess_executor.py
  class SubprocessContainerExecutor:
      def __init__(self, docker_bin: str = "docker"):
          self._docker = docker_bin

      def run(self, *, image_digest, command, mounts, network_policy, resource_limits):
          # 1. 验证镜像 digest（docker inspect --format '{{.Id}}' 对比）
          self._verify_digest(image_digest)
          # 2. 构造 docker run 命令
          args = ["docker", "run", "--rm",
                  "--user", "nonroot",
                  "--cap-drop", "ALL",
                  "--read-only",
                  "--network", "scoped-egress",  # 或 host.docker.internal 限通
                  "--memory", resource_limits.get("memory", "512m"),
                  "--cpus", str(resource_limits.get("cpus", 0.5)),
                  "--tmpfs", "/tmp:rw,noexec,nosuid",
                  image_digest] + list(command)
          # 3. mounts: -v src:dst
          for dst, src in mounts.items():
              args[6:6] = ["-v", f"{src}:{dst}"]
          # 4. 执行
          proc = subprocess.run(args, capture_output=True, text=True, timeout=600)
          return ContainerResult(stdout=proc.stdout, stderr=proc.stderr,
                                 exit_code=proc.returncode, artifacts_dir=...)
  ```
  - digest 验证：`docker inspect <image>@<digest> --format '{{.Id}}'`，对比预期 digest
  - scoped egress：用 Docker network `scoped-egress`（A1 创建，配 nftables 规则阻 metadata/DB/Docker host）
  - 超时：subprocess timeout 600s，超时 ContainerResult.exit_code=124

- [ ] **Step 4: GREEN** - 真实跑 nuclei 扫 httpbin，验证 stdout 有 JSONL 输出

- [ ] **Step 5: 在 AdapterRunner 接入** - 修改 `infrastructure/adapters/base.py` 默认用 SubprocessContainerExecutor（或注入），保留 mock 用于单元测试

- [ ] **Step 6: 提交** `git add src/secopent/infrastructure/adapters/subprocess_executor.py tests/integration/test_subprocess_executor.py && git commit -m "feat(adapters): add real subprocess container executor"`

**验收 A2：** 4 集成测试绿（nuclei 真跑 + 安全 flags + digest 校验 + metadata 阻断）

---

## Task A3: 真实 E2E + 除虫

**Files:** `tests/e2e_real/test_juice_shop_real.py`, `test_crapi_real.py`, `test_httpbin_real.py` + 修 parser/adapter bug

- [ ] **Step 1: 真实 E2E 测试**（替换 `tests/e2e/test_full_e2e.py` 的 mock executor）
  ```python
  # tests/e2e_real/test_juice_shop_real.py
  @pytest.mark.e2e_real
  def test_juice_shop_real_sqli():
      """真实跑 nuclei 扫 Juice Shop，oracle 验证 SQLi finding，覆盖门禁，报告。"""
      # 1. 起 Juice Shop（docker-compose）
      # 2. scope_snapshot include http://localhost:3000
      # 3. Planner 生成 DAG（TestCatalog WEB_APP 必修类）
      # 4. Orchestrator + SubprocessContainerExecutor 真跑 nuclei
      # 5. 解析真实 nuclei 输出 -> Observation
      # 6. oracle N/N 验证 SQLi Candidate
      # 7. 覆盖门禁 + 报告
      assert report.has_confirmed_finding(cwe="CWE-89")
  ```

- [ ] **Step 2: 跑真实 E2E，收集 bug**
  - `py -3.12 -m pytest -q tests/e2e_real/ -m e2e_real`
  - 预期：首批大量失败（parser 偏差、scope 边界、工具输出格式、超时、网络）
  - 记录每个失败原因

- [ ] **Step 3: 修 parser 偏差**（最常见）
  - 真实 nuclei JSONL 字段与 fixture 不完全一致（如 `matched` vs `matched-at`、`info.severity` 嵌套）
  - 修 `src/secopent/integrations/adapters/nuclei/__init__.py` parser 兼容真实输出
  - 更新 fixture（用真实输出样本替换，保持 fixture 测试）
  - 同理修 subfinder/httpx/naabu/nmap/dalfox 等 parser

- [ ] **Step 4: 修 scope 边界**
  - 真实目标 `http://localhost:3000` vs scope `http://localhost:3000` 匹配
  - `host.docker.internal` 解析（容器内访问宿主机靶场）
  - cloud-account scope 在真实 Prowler 跑时的边界

- [ ] **Step 5: 修超时/网络**
  - 真实 nuclei 扫大目标超时，调 timeout + 分批
  - 网络抖动导致 false negative，重试策略

- [ ] **Step 6: 三靶场全绿**
  - `py -3.12 -m pytest -q tests/e2e_real/ -m e2e_real` 全绿
  - 每靶场至少 1 个 Confirmed Finding（Juice Shop SQLi / crAPI IDOR / httpbin XSS 或其他）

- [ ] **Step 7: 提交** `git add tests/e2e_real/ src/secopent/integrations/adapters/ && git commit -m "test(e2e): real end-to-end with three ranges + parser fixes"`

**验收 A3：** 三靶场真实 E2E 绿，每靶场至少 1 Confirmed Finding，parser 兼容真实工具输出

---

## Task A4: ptai 真实集成

**Files:** `src/secopent/infrastructure/oracle/ptai_adapter.py`（修改去 lazy import）, `tests/integration/test_ptai_oracle.py`

- [ ] **Step 1: 装 ptai**
  - `py -3.12 -m pip install ptai`
  - 验证：`py -3.12 -c "import ptai; print(ptai.__version__)"`

- [ ] **Step 2: 集成测试**
  ```python
  # tests/integration/test_ptai_oracle.py
  @pytest.mark.integration
  def test_ptai_oracle_confirms_real_sqli():
      """真实 ptai oracle 验证 Juice Shop SQLi Candidate。"""
      candidate = make_sqli_candidate(target="http://localhost:3000")
      method = VerificationMethodRegistry.default_registry().get("sqli_time_based")
      oracle = OracleEngine(ptai_adapter=PtaiAdapter())
      result = oracle.verify(candidate, method)
      assert result.outcome == VerificationOutcome.CONFIRMED
      assert result.reproductions == method.default_n

  @pytest.mark.integration
  def test_ptai_oracle_refutes_false_positive():
      """ptai oracle 对非漏洞 Candidate 返回 REFUTED。"""
      ...
  ```

- [ ] **Step 3: 修 ptai 适配**（若 API 不匹配）
  - 检查 ptai 真实 API（`ptai.verify(...)` 签名），修 `ptai_adapter.py`
  - 去 lazy import（A 阶段 ptai 必装）

- [ ] **Step 4: oracle ground-truth 靶场集回归**
  - `py -3.12 -m pytest -q tests/oracle_ground_truth/ -m integration` 真实跑
  - 9 测试绿（Juice Shop/crAPI/vulhub 已知漏洞 oracle 确认）

- [ ] **Step 5: 提交** `git add src/secopent/infrastructure/oracle/ptai_adapter.py tests/integration/test_ptai_oracle.py && git commit -m "feat(oracle): real ptai integration with ground truth regression"`

**验收 A4：** ptai 真实装+跑，oracle 靶场集 9 测试绿，N/N 复证真实工作

---

## Task A5: Web Case Studio 浏览器实测

**Files:** `tests/web/test_case_studio_browser.py`（Playwright）, 修前端 bug

- [ ] **Step 1: 装 Playwright**
  - `py -3.12 -m pip install playwright && py -3.12 -m playwright install chromium`

- [ ] **Step 2: 浏览器测试 7 页**
  ```python
  # tests/web/test_case_studio_browser.py
  @pytest.mark.browser
  def test_case_studio_7_pages(page, api_server):
      """7 页可达 + 关键交互。"""
      # 1. Dashboard
      page.goto("http://localhost:8000/")
      assert "SecOpent" in page.title()
      # 2. NewAssessment
      page.goto("http://localhost:8000/assessments/new")
      page.fill("[name=project_id]", "test-proj")
      page.click("button[type=submit]")
      # 3. AssessmentDetail
      # 4. ApprovalCenter
      # 5. Findings
      # 6. CaseStudio（模型编辑 + YAML + 签名）
      # 7. Updates
  ```

- [ ] **Step 3: 跑浏览器测试，修前端 bug**
  - 启 API server：`py -3.12 -m secopent.interfaces.api.main`
  - `py -3.12 -m pytest -q tests/web/ -m browser`
  - 修前端 JS/CSS/路由 bug，修后端 API 不一致

- [ ] **Step 4: Case Studio 模型建模实测**
  - 浏览器里建一个 AppModel（导入 OpenAPI -> LLM 起草 -> 人校验 -> 签名 -> 生成 5 类测试）
  - 验证 signature 幂等 + DriftDetector

- [ ] **Step 5: 提交** `git add tests/web/ src/secopent/interfaces/web/ && git commit -m "test(web): browser test 7 pages + frontend fixes"`

**验收 A5：** 7 页浏览器可用，Case Studio 模型建模+签名+生成测试全流程通

---

## Task A6: LLM 真实接入

**Files:** `src/secopent/infrastructure/llm/`（新增 backend）, `src/secopent/application/remote_model.py`（修改）, `tests/integration/test_real_llm_gateway.py`

- [ ] **Step 1: LLM backend 实现**
  - `src/secopent/infrastructure/llm/ollama_backend.py`：调本地 Ollama（`http://localhost:11434/api/generate`）
  - `src/secopent/infrastructure/llm/remote_api_backend.py`：调远程 API（OpenAI/Claude/Gemini，用 httpx）
  - 都实现 `LLMBackend` Protocol（generate(prompt, max_tokens) -> response）

- [ ] **Step 2: RemoteModelGateway 接 backend**
  - 修改 `application/remote_model.py`：注入 LLMBackend
  - 配置：`config/llm.yaml` 选 backend + 模型 + 预算/限速

- [ ] **Step 3: 集成测试**
  ```python
  # tests/integration/test_real_llm_gateway.py
  @pytest.mark.integration
  def test_llm_gateway_redacts_sensitive():
      """SENSITIVE 数据脱敏后发 LLM。"""
      gateway = RemoteModelGateway(backend=OllamaBackend(model="qwen2.5:7b"))
      response = gateway.call(
          prompt="Summarize: password=hunter2 admin@corp.com",
          data_classification=DataClassification.SENSITIVE,
      )
      # 验证发到 LLM 的 prompt 不含 password/email（脱敏）
      # 验证审计记录调用
      assert "hunter2" not in gateway.last_sent_prompt
      assert "admin@corp.com" not in gateway.last_sent_prompt

  @pytest.mark.integration
  def test_llm_gateway_restricted_denied():
      """RESTRICTED 数据默认禁止发 LLM。"""
      with pytest.raises(RestrictedDataDenied):
          gateway.call(prompt="...", data_classification=DataClassification.RESTRICTED)

  @pytest.mark.integration
  def test_llm_gateway_budget_degradation():
      """超预算降级到本地或拒绝。"""
      # 模拟超 500K token/天 -> 降级
      ...
  ```

- [ ] **Step 4: AppModel LLM 起草实测**
  - 真实 LLM 起草 AppModel（喂 OpenAPI -> LLM 提议状态机 -> 人校验）
  - 验证 LLM 仅 PROPOSE，人审签名

- [ ] **Step 5: 提交** `git add src/secopent/infrastructure/llm/ src/secopent/application/remote_model.py tests/integration/test_real_llm_gateway.py && git commit -m "feat(llm): real ollama/remote backend with redaction and budget"`

**验收 A6：** LLM 真实接入，SENSITIVE 脱敏 + RESTRICTED 拒绝 + 预算降级 + 审计全工作

---

## Task A7: mypy infrastructure 清理

**Files:** `src/secopent/infrastructure/**/*.py`（修类型）, `pyproject.toml`（mypy 配置）

- [ ] **Step 1: 跑全仓 mypy，列错误**
  - `py -3.12 -m mypy src/secopent` -> 53 errors（据交接报告）
  - 分类：SQLAlchemy ORM 泛型（list/dict 缺参数）、adapter parser union-attr、API index 类型

- [ ] **Step 2: 修 SQLAlchemy ORM 泛型**
  - `Mapped[list]` -> `Mapped[list[str]]`（或 `Mapped[JSON]` 用自定义类型）
  - 所有 `core_*.py` + `catalog_models.py` + `intel_models.py` 等
  - 若 SQLAlchemy JSON 列类型难标，用 `Mapped[list[str]]` + `type_ignore` 或自定义 `JSONList` 类型

- [ ] **Step 3: 修 adapter parser union-attr**
  - `nuclei/__init__.py`、`openapi.py`、`postman.py` 等的 `.get()` null 检查
  - 加 `if x is None: return ()` 守卫

- [ ] **Step 4: 修 API/CLI 类型**
  - `interfaces/api/main.py` index 类型、`cli/main.py` 等

- [ ] **Step 5: 全仓 mypy clean**
  - `py -3.12 -m mypy src/secopent` -> 0 errors
  - 把 mypy strict 扩展到 infrastructure（`pyproject.toml` 加 `[[tool.mypy.overrides]] module = ["secopent.infrastructure.*"] strict = true`）

- [ ] **Step 6: 提交** `git add src/secopent/infrastructure/ pyproject.toml && git commit -m "fix(types): clean mypy infrastructure errors + extend strict"`

**验收 A7：** `py -3.12 -m mypy src/secopent` 0 errors（全仓 strict clean）

---

## Task A8: 阶段 A 收尾 + tag

- [ ] **Step 1: 全套验收**
  ```bash
  cd /f/claudepc/SecOpent
  py -3.12 -m pytest -q                    # 单元/集成全绿
  py -3.12 -m pytest -q -m integration     # 真实集成绿
  py -3.12 -m pytest -q -m e2e_real        # 真实 E2E 三靶场绿
  py -3.12 -m pytest -q -m browser         # 浏览器测试绿
  py -3.12 -m ruff check src tests
  py -3.12 -m mypy src/secopent            # 全仓 strict clean
  py -3.12 -m compileall -q src tests
  py -3.12 scripts/verify_env.py           # 环境全绿
  ```

- [ ] **Step 2: 真实渗透场景冒烟**（手动）
  - 用真实授权目标（或靶场）跑一次完整 Assessment
  - 验证：scope 强制 + 真实工具跑 + oracle 验证 + 覆盖门禁 + 报告
  - 记录任何运行时问题，修

- [ ] **Step 3: 文档**
  - `docs/deployment/environment-setup.md` 完善
  - `docs/deployment/troubleshooting.md` 写常见问题
  - README 更新：V1.0-usable 状态 + 真实使用步骤

- [ ] **Step 4: tag**
  - `git tag v1.0-usable`
  - Release notes：阶段 A 完成，产品可实际跑

**验收 A8（阶段 A 完成定义）：**
- ✅ 真实 Docker + 17 工具部署
- ✅ SubprocessContainerExecutor 真实跑
- ✅ 真实 E2E 三靶场绿
- ✅ ptai 真实集成 + 靶场集回归
- ✅ Interactsh 自托管 OOB 真实捕获
- ✅ Web Case Studio 浏览器 7 页可用
- ✅ LLM 真实接入 + 分级/脱敏/预算/降级
- ✅ mypy 全仓 strict clean
- ✅ 真实渗透场景冒烟通过
- ✅ `git tag v1.0-usable`

---

## 工期与依赖

```
A1 环境配给 (3-5天) ──► A2 SubprocessExecutor (3-5天) ──► A3 真实E2E+除虫 (1-2周)
                                                              │
                                                              ├──► A4 ptai (2-3天) [并行]
                                                              ├──► A5 Web浏览器 (3-5天) [并行]
                                                              └──► A6 LLM (2-3天) [并行]

A7 mypy清理 (2-3天) [独立，可并行]

A8 收尾 (2-3天) [A2-A7 全完后]
```

- A1 是硬前置（无 Docker 无法做 A2-A6）
- A2 是核心（真实执行器）
- A3 依赖 A2（真实 E2E 用真实执行器）
- A4/A5/A6 可与 A3 并行（都依赖 A1+A2 但相互独立）
- A7 独立（类型清理，随时做）
- A8 收尾依赖全部

**总工期：4-6 周**（单人全职，含除虫缓冲）

---

## 风险与缓解

| 风险 | 缓解 |
|---|---|
| Docker 在开发机装不上 | 阶段 A 前置必须；用云开发机或 WSL2 |
| 真实工具输出与 fixture 偏差大 | A3 预留 1-2 周除虫；用真实输出更新 fixture |
| ptai 不维护/API 变 | A4 若 ptai 不可用，回退自建 oracle（用其范式） |
| LLM 本地模型性能不足 | A6 远程 API 备选；预算/降级保护 |
| 真实 E2E 慢/不稳 | mark integration，CI 单独 job；本地按需跑 |
| Interactsh 公网域名难备 | 内网 DNS 指向 `oast.local` 测试；公网部署后置 |

---

## 下一步（阶段 A 完成后）

1. **真实场景验证**：拿授权目标做 1-2 次真实渗透，收集反馈
2. **阶段 B**（V1.1-stable）：基于反馈打磨（更多靶场回归 + 性能 + 策展补全 + 文档），6-8 周
3. **阶段 C**（V2）：远程 Worker + 多租户 + ToB，3-4 月

---

*阶段 A 完成后产品可实际跑渗透测试。执行方式同 M0-M5：subagent-driven + TDD（集成测试 mark integration）。*
