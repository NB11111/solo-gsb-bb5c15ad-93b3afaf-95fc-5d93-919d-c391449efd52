# Webhook Inbox

基于 FastAPI + SQLite 的 webhook 收件箱服务。接收事件、幂等去重、按时间游标分页查询、单条确认，数据持久化到 SQLite。

## 功能

- **POST /events** 提交事件（`event_id` / `type` / `payload`）
  - 并发重复请求只保留**首个版本**，所有重复请求返回与首次一致的结果
  - 相同 `event_id` 但内容（`type` 或 `payload`）不同 → **409 Conflict**
  - 内容比对是语义级的：JSON 键序不同但内容相同视为同一事件
- **POST /events/batch** 原子批量提交（1~100 个事件，结构同单条接口）
  - 批内同 `event_id` 内容语义相同 → 视为重复，映射到同一结果；内容不同 → **422** 并标出冲突下标
  - 与库中记录内容冲突 → **409** 并标出对应下标，**整批零写入**
  - 无冲突时**单一事务**写入全部新事件，按原输入顺序返回记录与每项 `created` 标记
- **GET /events** 按时间游标分页查询（键集分页，支持 `status` 过滤）
- **POST /events/{event_id}/ack** 单条确认（幂等，重复确认返回当前状态）
- **GET /events/{event_id}** 查询单条事件
- 事件与处理状态（`pending` / `acked`）持久化到 SQLite，**启动时自动建表**

## 快速开始（Docker，一键启动）

```bash
docker compose up --build
```

服务监听容器内 8000 端口，Compose 已映射到宿主机 **8000** 端口：

- API 地址： http://localhost:8000
- 交互式文档（Swagger UI）： http://localhost:8000/docs
- 健康检查： `curl http://localhost:8000/healthz`

SQLite 数据文件存放在命名卷 `webhook-data`（容器内 `/data/events.db`），容器重建后数据不丢失。

不使用 Compose 也可以：

```bash
docker build -t webhook-inbox .
docker run -d -p 8000:8000 -v webhook-data:/data webhook-inbox
```

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/events` | 提交事件。首次 `201`，重复（内容相同）`200`，内容冲突 `409` |
| POST | `/events/batch` | 原子批量提交（1~100 个）。有新事件 `201`，全部重复 `200`；批内冲突 `422`、与库冲突 `409`，均整批零写入 |
| GET | `/events?limit=&cursor=&status=` | 时间游标分页查询，`limit` 默认 50、最大 200 |
| GET | `/events/{event_id}` | 查询单条事件，不存在 `404` |
| POST | `/events/{event_id}/ack` | 确认事件（幂等），不存在 `404` |
| GET | `/healthz` | 健康检查 |

### 提交事件

```bash
curl -i -X POST http://localhost:8000/events \
  -H 'Content-Type: application/json' \
  -d '{"event_id": "evt-001", "type": "order.paid", "payload": {"amount": 100}}'
```

首次返回 `201`；再次提交相同内容返回 `200`，响应体与首次完全一致（均为首个版本的数据）：

```json
{
  "event_id": "evt-001",
  "type": "order.paid",
  "payload": {"amount": 100},
  "status": "pending",
  "created_at": "2026-09-20T12:00:00.000000Z",
  "acked_at": null
}
```

相同 `event_id` 不同内容返回 `409`：

```json
{"detail": "event_id 'evt-001' already exists with different content"}
```

### 批量提交事件

```bash
curl -i -X POST http://localhost:8000/events/batch \
  -H 'Content-Type: application/json' \
  -d '{
    "events": [
      {"event_id": "evt-101", "type": "order.paid", "payload": {"amount": 100}},
      {"event_id": "evt-102", "type": "order.paid", "payload": {"amount": 200}},
      {"event_id": "evt-101", "type": "order.paid", "payload": {"amount": 100}}
    ]
  }'
```

一次提交 1~100 个事件（结构与单条接口相同），整批原子写入：要么全部落库，要么零写入。响应按**原输入顺序**返回，每项附带 `created` 标记；批内相同 `event_id` 且内容语义相同（键序无关）视为重复，映射到同一结果（下例中第 1、3 项完全相同）。任一事件为新事件时返回 `201`，全部已存在时返回 `200`：

```json
{
  "items": [
    {"event_id": "evt-101", "type": "order.paid", "payload": {"amount": 100}, "status": "pending", "created_at": "2026-09-21T03:00:00.000000Z", "acked_at": null, "created": true},
    {"event_id": "evt-102", "type": "order.paid", "payload": {"amount": 200}, "status": "pending", "created_at": "2026-09-21T03:00:00.000100Z", "acked_at": null, "created": true},
    {"event_id": "evt-101", "type": "order.paid", "payload": {"amount": 100}, "status": "pending", "created_at": "2026-09-21T03:00:00.000000Z", "acked_at": null, "created": true}
  ]
}
```

批内同一 `event_id` 内容不同 → `422`，标出冲突下标，整批零写入：

```json
{
  "detail": {
    "message": "duplicate event_id with different content in batch",
    "conflicts": [{"event_id": "evt-101", "indices": [0, 2]}]
  }
}
```

与库中已存事件内容冲突 → `409`，同样标出对应下标，整批零写入且已存首版不被覆盖：

```json
{
  "detail": {
    "message": "events already exist with different content",
    "conflicts": [{"event_id": "evt-101", "indices": [1]}]
  }
}
```

### 分页查询

```bash
# 第一页
curl "http://localhost:8000/events?limit=2"
# 用响应中的 next_cursor 取下一页
curl "http://localhost:8000/events?limit=2&cursor=<next_cursor>"
# 只看未确认的事件
curl "http://localhost:8000/events?status=pending"
```

响应：

```json
{
  "items": [ ... ],
  "next_cursor": "eyJjcmVhdGVkX2F0Ijoi...",
  "has_more": true
}
```

事件按 `(created_at, event_id)` 升序排列；`next_cursor` 为不透明游标（base64 编码的时间 + ID），`has_more=false` 时 `next_cursor` 为 `null`。非法游标返回 `400`。

### 确认事件

```bash
curl -X POST http://localhost:8000/events/evt-001/ack
```

返回 `200`，`status` 变为 `acked` 并写入 `acked_at`；重复确认仍返回 `200`（幂等）。

## 幂等与并发设计

- 写入路径为 `INSERT OR IGNORE` + 同事务回读，由连接级锁保证原子性；SQLite（WAL 模式）串行化并发写，因此并发重复请求中只有一个真正落库，其余请求读到首个版本并原样返回。
- 内容指纹 = `SHA-256(type + 规范化JSON(payload))`（键排序、去空白），指纹不同即 `409`，已存数据不会被覆盖。批量接口在批内归并与库级比对中复用同一套指纹规则。
- 批量写入在**单一事务**内完成「查库比对 + 全部插入 + 回读」（连接级锁 + `BEGIN IMMEDIATE`），并发批次彼此串行：任一冲突即整批回滚，不产生部分提交，也不会覆盖首个版本。

## 配置

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DATABASE_PATH` | 容器内 `/data/events.db`，本地运行为 `./events.db` | SQLite 文件路径，父目录自动创建，启动时自动建表 |

修改宿主机端口映射：编辑 `docker-compose.yml` 中的 `ports`，如 `"8080:8000"`。

## 本地开发与测试

```bash
pip install -r requirements-dev.txt
pytest tests/ -q                 # 28 个测试：幂等、409、分页、ack、批量原子性、并发、持久化
DATABASE_PATH=./events.db uvicorn app.main:app --reload --port 8000
```

## 项目结构

```
app/
  main.py    # FastAPI 路由与请求模型
  store.py   # 幂等写入、游标分页、确认（存储层）
  db.py      # SQLite 连接、WAL、自动建表
tests/
  test_api.py
Dockerfile
docker-compose.yml
requirements.txt / requirements-dev.txt
```
