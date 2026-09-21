# Webhook Inbox

基于 FastAPI + SQLite 的 webhook 收件箱服务。接收事件、来源签名校验与重放防护、幂等去重、按时间游标分页查询、单条确认，数据持久化到 SQLite。

## 功能

- **POST /events** 提交事件（`event_id` / `type` / `payload`），**必须携带来源签名头**
  - 并发重复请求只保留**首个版本**，所有重复请求返回与首次一致的结果
  - 相同 `event_id` 但内容（`type` 或 `payload`）不同 → **409 Conflict**
  - 内容比对是语义级的：JSON 键序不同但内容相同视为同一事件
- **POST /events/batch** 原子批量提交（1~100 个事件，结构同单条接口），同样要求签名头
  - 批内同 `event_id` 内容语义相同 → 视为重复，映射到同一结果；内容不同 → **422** 并标出冲突下标
  - 与库中记录内容冲突 → **409** 并标出对应下标，**整批零写入**
  - 无冲突时**单一事务**写入全部新事件，按原输入顺序返回记录与每项 `created` 标记
- **来源签名与重放防护**（单条、批量同一套）
  - 必须携带 `X-Webhook-Source` / `X-Webhook-Timestamp` / `X-Webhook-Nonce` / `X-Webhook-Signature`
  - 签名串固定为 `timestamp + "\n" + nonce + "\n" + 原始请求体`，用来源密钥做 HMAC-SHA256，服务端常量时间比较
  - 时间戳与服务器时间偏差超过 **300 秒**、来源未知、签名错误、nonce 已被该来源使用 → 一律 **401 且零写入**
  - nonce 登记与事件入库处于**同一 SQLite 写事务**，并发重放中仅一个请求成功
  - 支持密钥轮换：旧密钥配 `previous_valid_until` 宽限期，到期自动失效
- **GET /events** 按时间游标分页查询（键集分页，支持 `status` 过滤）
- **POST /events/{event_id}/ack** 单条确认（幂等，重复确认返回当前状态）
- **GET /events/{event_id}** 查询单条事件
- 事件、nonce 与处理状态（`pending` / `acked`）持久化到 SQLite，**启动时自动建表，兼容既有数据库**

## 快速开始（Docker，一键启动）

```bash
docker compose up --build
```

服务监听容器内 **8000** 端口，Compose 已映射到宿主机 **8000** 端口：

- API 地址： http://localhost:8000
- 交互式文档（Swagger UI）： http://localhost:8000/docs
- 健康检查： `curl http://localhost:8000/healthz`

SQLite 数据文件存放在命名卷 `webhook-data`（容器内 `/data/events.db`），容器重建后数据不丢失。

`docker-compose.yml` 内置了一个演示来源密钥（来源名 `demo`，密钥 `demo-secret-change-me`），可直接联调；生产环境请通过环境变量覆盖为自己的密钥（见[配置](#配置)）。

不使用 Compose 也可以：

```bash
docker build -t webhook-inbox .
docker run -d -p 8000:8000 \
  -e WEBHOOK_SECRETS_JSON='{"demo":{"current":"demo-secret-change-me"}}' \
  -v webhook-data:/data webhook-inbox
```

## 来源签名

所有写接口（`POST /events`、`POST /events/batch`）都要求以下四个请求头：

| 请求头 | 说明 |
| --- | --- |
| `X-Webhook-Source` | 来源标识，需与 `WEBHOOK_SECRETS_JSON` 中的键一致，未知来源返回 401 |
| `X-Webhook-Timestamp` | Unix 时间戳（秒）。与服务器时间偏差 **>300 秒** 返回 401，防止囤积重放 |
| `X-Webhook-Nonce` | 一次性随机串（建议 UUID）。同一来源的 nonce 在约 600 秒（2 倍时间窗口）内不可复用 |
| `X-Webhook-Signature` | HMAC-SHA256 十六进制（hex）摘要，算法见下 |

签名串**固定**为（注意中间是换行符 `\n`，且必须对**原始请求体字节**签名，不要重新序列化 JSON）：

```
<timestamp> + "\n" + <nonce> + "\n" + <原始请求体>
```

即：

```
1789970000
7e8f9c1a2b3d4e5f8091a2b3c4d5e6f7
{"event_id":"evt-001","type":"order.paid","payload":{"amount":100}}
```

```
signature = HMAC_SHA256(key = <来源密钥>, message = 上面的签名串).hexdigest()
```

服务端使用常量时间比较（`hmac.compare_digest`）校验，且先验签再解析 JSON，因此任何畸形体或篡改体都不会被处理。

### 签名示例（Python）

```python
import hashlib
import hmac
import json
import time
import uuid

import httpx

source = "demo"
secret = "demo-secret-change-me"

event = {"event_id": "evt-001", "type": "order.paid", "payload": {"amount": 100}}
body = json.dumps(event, separators=(",", ":")).encode()  # 即为原始请求体
timestamp = str(int(time.time()))
nonce = uuid.uuid4().hex

message = timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body
signature = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
headers = {
    "X-Webhook-Source": source,
    "X-Webhook-Timestamp": timestamp,
    "X-Webhook-Nonce": nonce,
    "X-Webhook-Signature": signature,
}

r = httpx.post("http://localhost:8000/events", content=body, headers=headers)
print(r.status_code)  # 201
# 完全相同的请求再发一次（同 timestamp + nonce + body）-> 401 nonce already used
```

批量接口同理，只需把 `body` 换成 `json.dumps({"events": [...]})` 并请求 `/events/batch`。

### 命令行（curl + python3 计算签名）

```bash
BODY='{"event_id":"evt-001","type":"order.paid","payload":{"amount":100}}'
read TS NONCE SIG < <(python3 -c '
import sys, time, uuid, hmac, hashlib
body = sys.argv[1].encode()
ts, nonce = str(int(time.time())), uuid.uuid4().hex
msg = ts.encode() + b"\n" + nonce.encode() + b"\n" + body
print(ts, nonce, hmac.new(b"demo-secret-change-me", msg, hashlib.sha256).hexdigest())
' "$BODY")

curl -i -X POST http://localhost:8000/events \
  -H 'Content-Type: application/json' \
  -H "X-Webhook-Source: demo" \
  -H "X-Webhook-Timestamp: $TS" \
  -H "X-Webhook-Nonce: $NONCE" \
  -H "X-Webhook-Signature: $SIG" \
  --data-binary "$BODY"
```

> 注意必须用 `--data-binary`，不要用 `-d @文件` 之外会改变字节的方式；签名只认发出去的那一份原始字节。

### 拒绝行为（均为 401 且零写入）

- 缺少任一签名头、请求头超长、时间戳不是整数
- 时间戳偏离服务器时间超过 300 秒（新旧两个方向都拒绝）
- `X-Webhook-Source` 未在密钥配置中登记
- 签名不匹配（密钥错误、请求体被篡改、nonce/timestamp 与签名不一致）
- 同一来源的 nonce 在有效期内已被使用（无论原请求还是换体重放，也无论打在单条还是批量接口）

读接口（`GET /events`、`GET /events/{id}`、`POST /events/{id}/ack`、`GET /healthz`）不校验来源签名。

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/events` | 提交事件（需签名头）。首次 `201`，重复（内容相同）`200`，内容冲突 `409`，重放/验签失败 `401` |
| POST | `/events/batch` | 原子批量提交（1~100 个，需签名头）。有新事件 `201`，全部重复 `200`；批内冲突 `422`、与库冲突 `409`、重放 `401`，均整批零写入 |
| GET | `/events?limit=&cursor=&status=` | 时间游标分页查询，`limit` 默认 50、最大 200 |
| GET | `/events/{event_id}` | 查询单条事件，不存在 `404` |
| POST | `/events/{event_id}/ack` | 确认事件（幂等），不存在 `404` |
| GET | `/healthz` | 健康检查 |

### 提交事件

首次返回 `201`；再次提交相同内容（使用**新的** timestamp/nonce 重新签名）返回 `200`，响应体与首次完全一致（均为首个版本的数据）：

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

重放（复用同一 `timestamp + nonce`，或复用 nonce 对另一请求体重新签名）返回 `401`：

```json
{"detail": "nonce already used"}
```

相同 `event_id` 不同内容返回 `409`（签名与 nonce 均合法的前提下）：

```json
{"detail": "event_id 'evt-001' already exists with different content"}
```

### 批量提交事件

一次提交 1~100 个事件（结构与单条接口相同），整批原子写入：要么 nonce 与整批事件全部落库，要么零写入。响应按**原输入顺序**返回，每项附带 `created` 标记；批内相同 `event_id` 且内容语义相同（键序无关）视为重复，映射到同一结果。任一事件为新事件时返回 `201`，全部已存在时返回 `200`：

```json
{
  "items": [
    {"event_id": "evt-101", "type": "order.paid", "payload": {"amount": 100}, "status": "pending", "created_at": "2026-09-21T03:00:00.000000Z", "acked_at": null, "created": true},
    {"event_id": "evt-102", "type": "order.paid", "payload": {"amount": 200}, "status": "pending", "created_at": "2026-09-21T03:00:00.000100Z", "acked_at": null, "created": true},
    {"event_id": "evt-101", "type": "order.paid", "payload": {"amount": 100}, "status": "pending", "created_at": "2026-09-21T03:00:00.000000Z", "acked_at": null, "created": true}
  ]
}
```

批内同一 `event_id` 内容不同 → `422`，标出冲突下标，整批零写入；与库中已存事件内容冲突 → `409`，同样标出对应下标，整批零写入且已存首版不被覆盖：

```json
{
  "detail": {
    "message": "duplicate event_id with different content in batch",
    "conflicts": [{"event_id": "evt-101", "indices": [0, 2]}]
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

## 幂等、签名与并发设计

- **签名先于解析**：中间件依赖读取原始字节体验签，验签通过后才做 JSON 解析，畸形体/篡改体不会产生任何写入。
- **nonce 与事件同一写事务**：单条接口把「nonce 唯一插入 + 事件写入/回读」、批量接口把「nonce 唯一插入 + 查库比对 + 全部插入 + 回读」分别放进单个 `BEGIN IMMEDIATE` 事务，配合进程内单连接 + 连接级锁，SQLite 写操作串行化，并发重放中只有一个请求提交成功，其余全部 401。
- **nonce 表**：`used_nonces PRIMARY KEY (source, nonce)` 在数据库层兜底唯一性；登记时顺带清理超过 600 秒保留期的记录。因为时间戳只允许 ±300 秒，任何仍可能被接受的重放，其 nonce 在库中必定未过期。
- **事件幂等**：内容指纹 = `SHA-256(type + 规范化JSON(payload))`（键排序、去空白），指纹不同即 `409`，已存数据不会被覆盖。批量接口在批内归并与库级比对中复用同一套指纹规则。
- **密钥轮换**：见下节，旧密钥只在显式宽限期内可验签。

## 配置

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DATABASE_PATH` | 容器内 `/data/events.db`，本地运行为 `./events.db` | SQLite 文件路径，父目录自动创建，启动时自动建表 |
| `WEBHOOK_SECRETS_JSON` | Compose 内置 `{"demo": {"current": "demo-secret-change-me"}}`；本地运行未设置时为**空**（所有写请求 401） | 来源密钥 JSON，见下 |

`WEBHOOK_SECRETS_JSON` 是一个 JSON 对象，键为来源名（即 `X-Webhook-Source` 的取值），值为：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `current` | 是 | 现行密钥，非空字符串 |
| `previous` | 轮换时必填 | 上一密钥，宽限期内仍可用于验签 |
| `previous_valid_until` | 配了 `previous` 时必填 | 旧密钥失效时刻，ISO-8601 且**必须带时区**，如 `2026-10-01T00:00:00Z` |

配置非法（JSON 语法错误、字段缺失、时间戳不带时区等）会导致服务**启动失败**（fail-fast），避免误放行。

### 密钥轮换流程

1. 生成新密钥 `new-secret`，把旧密钥 `old-secret` 保留为 `previous`，设置宽限期截止时间：

   ```json
   {
     "billing": {
       "current": "new-secret",
       "previous": "old-secret",
       "previous_valid_until": "2026-10-01T00:00:00Z"
     }
   }
   ```

2. 通知各来源切换到新密钥；宽限期内新旧密钥签名均接受。
3. 宽限期过后移除 `previous` / `previous_valid_until`，只保留新 `current`：

   ```json
   {"billing": {"current": "new-secret"}}
   ```

多来源示例（Compose 中可用 `.env` 或直接改 `environment` 覆盖）：

```bash
export WEBHOOK_SECRETS_JSON='{
  "billing":  {"current": "billing-secret"},
  "partner-a": {"current": "a-new", "previous": "a-old", "previous_valid_until": "2026-10-01T00:00:00Z"}
}'
```

修改宿主机端口映射：编辑 `docker-compose.yml` 中的 `ports`，如 `"8080:8000"`（容器内固定监听 8000）。

## 本地开发与测试

```bash
pip install -r requirements-dev.txt
pytest tests/ -q                 # 62 个测试：签名/时间窗/nonce、批量原子性、并发重放、轮换宽限、旧库迁移、持久化
WEBHOOK_SECRETS_JSON='{"demo":{"current":"dev-secret"}}' \
  DATABASE_PATH=./events.db uvicorn app.main:app --reload --port 8000
```

## 项目结构

```
app/
  main.py    # FastAPI 路由、签名依赖与请求模型
  auth.py    # WEBHOOK_SECRETS_JSON 解析、HMAC 验签、时间窗与密钥宽限
  store.py   # nonce 登记与幂等写入（同一事务）、游标分页、确认
  db.py      # SQLite 连接、WAL、自动建表（events + used_nonces）
tests/
  test_api.py
Dockerfile
docker-compose.yml
requirements.txt / requirements-dev.txt
```
