# 核心边界（M0）

## 依赖方向
interfaces -> application -> domain
infrastructure / execution / integrations 通过 ports/contracts 接入
domain 不反向依赖基础设施（不导入 FastAPI/SQLAlchemy/Docker/MCP/httpx/cryptography）

## M0 表
- core_projects
- core_scope_snapshots
- core_assessments
- core_execution_plans
- core_approvals
- core_audit_events

## 禁止依赖
- domain: 无任何框架
- application: 无任何框架（仅 Protocol + Domain）
- infrastructure: 可依赖 SQLAlchemy 等基础设施库

## Repository Contract
M0 起抽象 Repository Protocol，SQLite WAL 实现 + PostgreSQL 接口预留。
M5 切 PG 时无需改 domain/application，仅新增 SqlAlchemy+PG 实现。
