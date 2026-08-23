# 快速开始(Getting Started)

> 5 分钟跑通本项目的最小演示。适合第一次接触项目的人 / 评估是否值得深入使用。

## 前置条件

| 项 | 要求 | 说明 |
|---|---|---|
| Python | 3.10+(推荐 3.12) | 项目主语言 |
| Git | 最新 | 拉取代码 |
| Docker | 24+ | 启动依赖服务(PostgreSQL / Redis / OpenSearch / Vector) |
| 磁盘 | ≥ 5 GB | 模型与依赖 |
| 内存 | ≥ 4 GB | LLM 推理或本地模型 |

## 第 1 步:克隆 & 装环境

```bash
git clone https://github.com/echocc00/REPO.git
cd REPO

# 创建虚拟环境
python3 -m venv .venv
source .venv/bin/activate    # macOS / Linux
# .venv\Scripts\activate     # Windows

# 装依赖(开发模式)
pip install -e ".[dev]"
```

## 第 2 步:启动依赖服务(Docker)

```bash
docker compose -f deploy/docker-compose.dev.yml up -d
```

> 如果项目没有 docker-compose.dev.yml,参见 `docs/deployment/environment-setup.md`。

## 第 3 步:配置环境变量

```bash
cp .env.example .env
# 编辑 .env,至少填:
# - LLM_API_KEY (DeepSeek / Qwen / OpenAI 任选)
# - 数据库连接(若不是默认)
```

## 第 4 步:初始化数据库

```bash
alembic upgrade head
# 或项目自定义的初始化脚本
python scripts/init_db.py
```

## 第 5 步:启动 & 验证

```bash
# 后端
uvicorn app.main:app --reload --port 8000
# 或项目自定义启动命令

# 另一终端 - 前端(如有)
cd frontend && npm install && npm run dev

# 访问
# 后端 API:    http://localhost:8000
# API 文档:    http://localhost:8000/docs
# 前端界面:    http://localhost:5173
```

## 验证清单

跑通下面 4 步即算"上手":

- [ ] `/health` 返回 200
- [ ] `/docs` 能看到 OpenAPI Swagger UI
- [ ] 跑测试套件:**`pytest -q`** 全部通过
- [ ] 前端 dashboard 能加载并显示 mock 数据

## 下一步

- 📖 阅读 [`docs/architecture/`](../docs/architecture/) 理解系统设计
- 🛠️ 跑 [`scripts/acceptance.py`](../../scripts/) 体验完整功能
- 🤝 看 [CONTRIBUTING.md](../../CONTRIBUTING.md)(如有)了解贡献流程
- 💼 商业合作:见 [README.md](../../README.md) 顶部"商业授权"段

## 常见问题

**Q: 启动后 8000 端口被占用?**
A: `lsof -i:8000` 查谁在用,或改 `--port 8001`。

**Q: 数据库连接失败?**
A: 检查 `docker compose ps` 确认 PostgreSQL 已启动;`.env` 里的 `DATABASE_URL` 格式正确。

**Q: LLM 调用 401?**
A: `.env` 里的 `LLM_API_KEY` 没填或填错。本项目**不内置 LLM**,需要你自己申请(DeepSeek/Qwen/MiniMax/OpenAI 都支持)。

**Q: 跑测试有 fixture 错误?**
A: 通常是依赖没装全:`pip install -e ".[dev]"` 重新装一遍。

---

> ⚠️ **本教程是**最小演示**,生产部署参见 `docs/deployment.md`**