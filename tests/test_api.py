import hashlib
import hmac
import json
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.db import Database
from app.main import app
from app.store import (
    BatchConflictError,
    EventConflictError,
    EventNotFoundError,
    EventStore,
    NonceReuseError,
)

DEMO_SECRET = "test-secret-key"
OTHER_SECRET = "other-secret-key"
DEFAULT_SECRETS = {
    "billing": {"current": DEMO_SECRET},
    "payments": {"current": OTHER_SECRET},
    "rotation": {
        "current": "rotated-new",
        "previous": "rotated-old",
        "previous_valid_until": "2099-01-01T00:00:00Z",
    },
    "expired": {
        "current": "exp-new",
        "previous": "exp-old",
        "previous_valid_until": "2000-01-01T00:00:00Z",
    },
}


def make_headers(
    body: bytes,
    *,
    source: str = "billing",
    secret: str = DEMO_SECRET,
    timestamp: str | int | None = None,
    nonce: str | None = None,
    omit: tuple[str, ...] = (),
) -> dict[str, str]:
    ts = str(int(time.time()) if timestamp is None else timestamp)
    nonce = nonce or uuid.uuid4().hex
    message = ts.encode() + b"\n" + nonce.encode() + b"\n" + body
    signature = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    headers = {
        "X-Webhook-Source": source,
        "X-Webhook-Timestamp": ts,
        "X-Webhook-Nonce": nonce,
        "X-Webhook-Signature": signature,
    }
    for name in omit:
        headers.pop(name, None)
    return headers


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("WEBHOOK_SECRETS_JSON", json.dumps(DEFAULT_SECRETS))
    with TestClient(app) as c:
        yield c


def make_client(tmp_path, monkeypatch, *, secrets: str | None):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / f"alt-{uuid.uuid4().hex}.db"))
    if secrets is None:
        monkeypatch.delenv("WEBHOOK_SECRETS_JSON", raising=False)
    else:
        monkeypatch.setenv("WEBHOOK_SECRETS_JSON", secrets)
    return TestClient(app)


def post_event(client, event: dict, **header_kw) -> tuple:
    body = json.dumps(event, separators=(",", ":")).encode()
    headers = make_headers(body, **header_kw)
    return client.post("/events", content=body, headers=headers), headers


def post_batch(client, events: list[dict], **header_kw) -> tuple:
    body = json.dumps({"events": events}, separators=(",", ":")).encode()
    headers = make_headers(body, **header_kw)
    return client.post("/events/batch", content=body, headers=headers), headers


def make_event(i: int) -> dict:
    return {"event_id": f"evt-{i:04d}", "type": "user.created", "payload": {"n": i}}


# ---------- API 层：签名与重放防护 ----------


def test_unsigned_post_rejected_401_zero_writes(client):
    r = client.post("/events", json=make_event(1))
    assert r.status_code == 401
    r2 = client.post("/events/batch", json={"events": [make_event(1)]})
    assert r2.status_code == 401
    assert client.get("/events").json()["items"] == []  # 零写入


def test_missing_any_required_header_is_401(client):
    body = json.dumps(make_event(1)).encode()
    for missing in ("X-Webhook-Source", "X-Webhook-Timestamp", "X-Webhook-Nonce", "X-Webhook-Signature"):
        headers = make_headers(body, omit=(missing,))
        r = client.post("/events", content=body, headers=headers)
        assert r.status_code == 401, missing


def test_unknown_source_is_401(client):
    body = json.dumps(make_event(1)).encode()
    r = client.post("/events", content=body, headers=make_headers(body, source="stranger"))
    assert r.status_code == 401
    assert client.get("/events").json()["items"] == []


def test_bad_signature_is_401(client):
    body = json.dumps(make_event(1)).encode()
    headers = make_headers(body, secret=OTHER_SECRET)  # 不是任一来源的密钥
    r = client.post("/events", content=body, headers=headers)
    assert r.status_code == 401
    assert client.get("/events").json()["items"] == []


def test_signature_must_cover_exact_raw_body(client):
    body = json.dumps(make_event(1)).encode()
    headers = make_headers(body)
    tampered = json.dumps(make_event(2)).encode()  # 体被篡改，签名不匹配
    r = client.post("/events", content=tampered, headers=headers)
    assert r.status_code == 401
    assert client.get("/events").json()["items"] == []


@pytest.mark.parametrize("delta", [-301, 301, -3600, 3600])
def test_timestamp_outside_window_is_401(client, delta):
    body = json.dumps(make_event(1)).encode()
    headers = make_headers(body, timestamp=int(time.time()) + delta)
    assert client.post("/events", content=body, headers=headers).status_code == 401
    assert client.get("/events").json()["items"] == []


@pytest.mark.parametrize("delta", [-299, 0, 299])
def test_timestamp_within_window_accepted(client, delta):
    body = json.dumps(make_event(delta)).encode()
    headers = make_headers(body, timestamp=int(time.time()) + delta)
    assert client.post("/events", content=body, headers=headers).status_code == 201


def test_timestamp_boundary_is_inclusive():
    # “偏离超过 300 秒”才拒绝：恰好 300 秒接受，301 秒拒绝。
    from app.auth import Signer, WebhookAuthError, load_secrets

    signer = Signer(load_secrets(json.dumps(DEFAULT_SECRETS)))
    now = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)
    body = b"{}"

    def lower_headers(delta):
        return {k.lower(): v for k, v in make_headers(body, timestamp=int(now.timestamp()) + delta).items()}

    for delta in (-300, 300):
        assert signer.verify(lower_headers(delta), body, now=now)[0] == "billing"
    for delta in (-301, 301):
        with pytest.raises(WebhookAuthError):
            signer.verify(lower_headers(delta), body, now=now)


def test_non_integer_timestamp_is_401(client):
    body = json.dumps(make_event(1)).encode()
    headers = make_headers(body, timestamp="not-a-number")
    assert client.post("/events", content=body, headers=headers).status_code == 401


def test_nonce_replay_on_same_endpoint_is_401(client):
    body = json.dumps(make_event(1)).encode()
    headers = make_headers(body)
    assert client.post("/events", content=body, headers=headers).status_code == 201
    # 完全相同的请求（头 + 体）重放
    assert client.post("/events", content=body, headers=headers).status_code == 401
    assert len(client.get("/events").json()["items"]) == 1  # 只有一条


def test_nonce_reuse_even_with_resigned_different_body_is_401(client):
    first_body = json.dumps(make_event(1)).encode()
    headers = make_headers(first_body)
    client.post("/events", content=first_body, headers=headers)
    # nonce 复用到另一条事件上（签名对新体仍然有效）
    other_body = json.dumps(make_event(2)).encode()
    ts = str(int(time.time()))
    nonce = headers["X-Webhook-Nonce"]
    message = ts.encode() + b"\n" + nonce.encode() + b"\n" + other_body
    sig = hmac.new(DEMO_SECRET.encode(), message, hashlib.sha256).hexdigest()
    headers2 = {
        "X-Webhook-Source": "billing",
        "X-Webhook-Timestamp": ts,
        "X-Webhook-Nonce": nonce,
        "X-Webhook-Signature": sig,
    }
    r = client.post("/events", content=other_body, headers=headers2)
    assert r.status_code == 401
    assert client.get("/events/evt-0002").status_code == 404  # 重放零写入


def test_nonce_reuse_across_single_and_batch_is_401(client):
    body = json.dumps(make_event(1)).encode()
    headers = make_headers(body)
    assert client.post("/events", content=body, headers=headers).status_code == 201

    batch_body = json.dumps({"events": [make_event(2)]}).encode()
    ts = str(int(time.time()))
    nonce = headers["X-Webhook-Nonce"]
    message = ts.encode() + b"\n" + nonce.encode() + b"\n" + batch_body
    sig = hmac.new(DEMO_SECRET.encode(), message, hashlib.sha256).hexdigest()
    r = client.post(
        "/events/batch",
        content=batch_body,
        headers={
            "X-Webhook-Source": "billing",
            "X-Webhook-Timestamp": ts,
            "X-Webhook-Nonce": nonce,
            "X-Webhook-Signature": sig,
        },
    )
    assert r.status_code == 401
    assert client.get("/events/evt-0002").status_code == 404


def test_same_nonce_value_scoped_per_source(client):
    # 不同来源各自的 nonce 空间互不影响
    shared_nonce = uuid.uuid4().hex
    body1 = json.dumps(make_event(1)).encode()
    body2 = json.dumps(make_event(2)).encode()
    h1 = make_headers(body1, source="billing", nonce=shared_nonce)
    h2 = make_headers(body2, source="payments", secret=OTHER_SECRET, nonce=shared_nonce)
    assert client.post("/events", content=body1, headers=h1).status_code == 201
    assert client.post("/events", content=body2, headers=h2).status_code == 201
    # 但同来源再用一次即重放
    body3 = json.dumps(make_event(3)).encode()
    h3 = make_headers(body3, source="billing", nonce=shared_nonce)
    assert client.post("/events", content=body3, headers=h3).status_code == 401


def test_previous_key_accepted_within_grace_period(client):
    body = json.dumps(make_event(1)).encode()
    headers = make_headers(body, source="rotation", secret="rotated-old")
    r = client.post("/events", content=body, headers=headers)
    assert r.status_code == 201  # 旧密钥在 previous_valid_until 之前仍有效


def test_previous_key_rejected_after_grace_period(client):
    body = json.dumps(make_event(1)).encode()
    headers = make_headers(body, source="expired", secret="exp-old")
    r = client.post("/events", content=body, headers=headers)
    assert r.status_code == 401  # 宽限期已过，旧签名拒绝
    assert client.get("/events").json()["items"] == []


def test_batch_replay_is_401_and_zero_writes(client):
    events = [make_event(1), make_event(2)]
    (r, headers) = post_batch(client, events)
    assert r.status_code == 201
    body = json.dumps({"events": events}, separators=(",", ":")).encode()
    r2 = client.post("/events/batch", content=body, headers=headers)
    assert r2.status_code == 401
    assert len(client.get("/events").json()["items"]) == 2


def test_batch_intra_conflict_does_not_consume_nonce(client):
    events = [
        {"event_id": "e1", "type": "t", "payload": {"v": 1}},
        {"event_id": "e1", "type": "t", "payload": {"v": 999}},
    ]
    (r, headers) = post_batch(client, events)
    assert r.status_code == 422  # 批内冲突在写事务之前
    body = json.dumps({"events": events[:1]}, separators=(",", ":")).encode()
    # nonce 未被消费：同一 nonce 配新的合法签名体仍可成功
    ts = str(int(time.time()))
    nonce = headers["X-Webhook-Nonce"]
    sig = hmac.new(DEMO_SECRET.encode(), ts.encode() + b"\n" + nonce.encode() + b"\n" + body, hashlib.sha256).hexdigest()
    r2 = client.post(
        "/events/batch",
        content=body,
        headers={
            "X-Webhook-Source": "billing",
            "X-Webhook-Timestamp": ts,
            "X-Webhook-Nonce": nonce,
            "X-Webhook-Signature": sig,
        },
    )
    assert r2.status_code == 201


def test_no_secrets_configured_rejects_everything(tmp_path, monkeypatch):
    c = make_client(tmp_path, monkeypatch, secrets=None)
    with c:
        body = json.dumps(make_event(1)).encode()
        assert c.post("/events", content=body, headers=make_headers(body)).status_code == 401


def test_invalid_secrets_config_fails_startup(tmp_path, monkeypatch):
    c = make_client(tmp_path, monkeypatch, secrets="{not json")
    with pytest.raises(ValueError):
        with c:
            pass


def test_invalid_previous_valid_until_fails_startup(tmp_path, monkeypatch):
    c = make_client(
        tmp_path,
        monkeypatch,
        secrets=json.dumps({"s": {"current": "a", "previous": "b", "previous_valid_until": "soon"}}),
    )
    with pytest.raises(ValueError):
        with c:
            pass


def test_malformed_json_body_with_valid_signature_is_422(client):
    body = b"{not valid json"
    r = client.post("/events", content=body, headers=make_headers(body))
    assert r.status_code == 422
    assert client.get("/events").json()["items"] == []  # nonce 未进入写事务


# ---------- API 层：既有功能 ----------


def test_create_event_returns_201(client):
    r, _ = post_event(client, make_event(1))
    assert r.status_code == 201
    body = r.json()
    assert body["event_id"] == "evt-0001"
    assert body["type"] == "user.created"
    assert body["payload"] == {"n": 1}
    assert body["status"] == "pending"
    assert body["acked_at"] is None
    assert body["created_at"]


def test_duplicate_same_content_returns_consistent_result(client):
    first, _ = post_event(client, make_event(1))
    dup, _ = post_event(client, make_event(1))  # 不同 nonce，合法的重复投递
    assert first.status_code == 201
    assert dup.status_code == 200
    assert dup.json() == first.json()  # 返回与首个版本一致的结果


def test_duplicate_is_semantic_not_textual(client):
    post_event(client, {"event_id": "e1", "type": "t", "payload": {"a": 1, "b": 2}})
    r, _ = post_event(client, {"event_id": "e1", "type": "t", "payload": {"b": 2, "a": 1}})
    assert r.status_code == 200  # 键序不同但语义相同，不算冲突


def test_same_id_different_content_returns_409(client):
    post_event(client, make_event(1))
    r, _ = post_event(
        client, {"event_id": "evt-0001", "type": "user.created", "payload": {"n": 999}}
    )
    assert r.status_code == 409
    r2, _ = post_event(
        client, {"event_id": "evt-0001", "type": "other.type", "payload": {"n": 1}}
    )
    assert r2.status_code == 409
    # 冲突写入不会覆盖首个版本（且 nonce 未被消费，否则连请求都发不出）
    assert client.get("/events/evt-0001").json()["payload"] == {"n": 1}


def test_validation_error(client):
    # Pydantic 模型层的校验在验签之后：构造对实际发送体的合法签名
    event = {"event_id": "x"}
    body = json.dumps(event).encode()
    assert client.post("/events", content=body, headers=make_headers(body)).status_code == 422
    event2 = {"event_id": "", "type": "t", "payload": {}}
    body2 = json.dumps(event2).encode()
    assert client.post("/events", content=body2, headers=make_headers(body2)).status_code == 422


def test_get_single_event(client):
    post_event(client, make_event(1))
    r = client.get("/events/evt-0001")
    assert r.status_code == 200
    assert r.json()["event_id"] == "evt-0001"
    assert client.get("/events/nope").status_code == 404


def test_pagination_walks_all_events_in_order(client):
    for i in range(25):
        post_event(client, make_event(i))

    seen, cursor, pages = [], None, 0
    while True:
        params = {"limit": 10}
        if cursor:
            params["cursor"] = cursor
        r = client.get("/events", params=params)
        assert r.status_code == 200
        body = r.json()
        seen.extend(item["event_id"] for item in body["items"])
        cursor = body["next_cursor"]
        pages += 1
        if not body["has_more"]:
            break

    assert pages == 3
    assert len(seen) == 25
    assert len(set(seen)) == 25  # 无重复
    assert seen == sorted(seen)  # 按 event_id 字典序（此处与时间序一致）
    assert cursor is None


def test_pagination_invalid_cursor(client):
    assert client.get("/events", params={"cursor": "!!!bad!!!"}).status_code == 400


def test_status_filter(client):
    for i in range(5):
        post_event(client, make_event(i))
    client.post("/events/evt-0001/ack")
    client.post("/events/evt-0003/ack")

    pending = client.get("/events", params={"status": "pending"}).json()
    acked = client.get("/events", params={"status": "acked"}).json()
    assert len(pending["items"]) == 3
    assert len(acked["items"]) == 2
    assert {i["event_id"] for i in acked["items"]} == {"evt-0001", "evt-0003"}


def test_ack_event(client):
    post_event(client, make_event(1))
    r = client.post("/events/evt-0001/ack")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "acked"
    assert body["acked_at"]

    again = client.post("/events/evt-0001/ack")  # 幂等
    assert again.status_code == 200
    assert again.json()["status"] == "acked"

    assert client.get("/events/evt-0001").json()["status"] == "acked"


def test_ack_not_found(client):
    assert client.post("/events/nope/ack").status_code == 404


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_read_endpoints_do_not_require_signatures(client):
    # 查询 / ack 为内部接口，不要求来源签名
    post_event(client, make_event(1))
    assert client.get("/events").status_code == 200
    assert client.get("/events/evt-0001").status_code == 200
    assert client.post("/events/evt-0001/ack").status_code == 200


# ---------- 批量接口 ----------


def test_batch_create_all_new(client):
    events = [make_event(i) for i in range(3)]
    r, _ = post_batch(client, events)
    assert r.status_code == 201
    items = r.json()["items"]
    assert [it["event_id"] for it in items] == [e["event_id"] for e in events]  # 原输入顺序
    assert all(it["created"] for it in items)
    assert all(it["status"] == "pending" for it in items)
    for e in events:  # 全部落库
        assert client.get(f"/events/{e['event_id']}").status_code == 200


def test_batch_intra_duplicates_map_to_same_result(client):
    events = [
        {"event_id": "e1", "type": "t", "payload": {"a": 1, "b": 2}},
        {"event_id": "e2", "type": "t", "payload": {"x": 1}},
        {"event_id": "e1", "type": "t", "payload": {"b": 2, "a": 1}},  # 键序不同，语义相同
    ]
    r, _ = post_batch(client, events)
    assert r.status_code == 201
    items = r.json()["items"]
    assert items[0] == items[2]  # 重复项映射到同一结果（含 created 标记）
    assert items[0]["created"] is True
    assert len(client.get("/events").json()["items"]) == 2  # 只落库两条


def test_batch_intra_conflict_returns_422_and_zero_writes(client):
    events = [
        {"event_id": "e1", "type": "t", "payload": {"v": 1}},
        {"event_id": "e2", "type": "t", "payload": {"v": 2}},
        {"event_id": "e1", "type": "t", "payload": {"v": 999}},
    ]
    r, _ = post_batch(client, events)
    assert r.status_code == 422
    assert r.json()["detail"]["conflicts"] == [{"event_id": "e1", "indices": [0, 2]}]
    assert client.get("/events").json()["items"] == []  # 整批零写入


def test_batch_db_conflict_returns_409_and_zero_writes(client):
    post_event(client, {"event_id": "e1", "type": "t", "payload": {"v": 1}})
    events = [
        {"event_id": "e2", "type": "t", "payload": {"v": 2}},
        {"event_id": "e1", "type": "t", "payload": {"v": 999}},  # 与库中首版冲突
    ]
    r, _ = post_batch(client, events)
    assert r.status_code == 409
    assert r.json()["detail"]["conflicts"] == [{"event_id": "e1", "indices": [1]}]
    assert client.get("/events/e2").status_code == 404  # 整批零写入
    assert client.get("/events/e1").json()["payload"] == {"v": 1}  # 首版未被覆盖


def test_batch_db_conflict_reports_all_indices_of_duplicates(client):
    post_event(client, {"event_id": "e1", "type": "t", "payload": {"v": 1}})
    dup = {"event_id": "e1", "type": "t", "payload": {"v": 2}}
    r, _ = post_batch(client, [dup, make_event(5), dup])
    assert r.status_code == 409
    assert r.json()["detail"]["conflicts"] == [{"event_id": "e1", "indices": [0, 2]}]
    assert client.get("/events/evt-0005").status_code == 404


def test_batch_existing_same_content_marked_not_created(client):
    first, _ = post_event(client, make_event(1))
    r, _ = post_batch(client, [make_event(1), make_event(2)])
    assert r.status_code == 201  # 含有新事件
    items = r.json()["items"]
    assert items[0]["created"] is False
    assert items[0]["created_at"] == first.json()["created_at"]  # 返回库中首个版本
    assert items[1]["created"] is True


def test_batch_all_duplicates_returns_200(client):
    post_event(client, make_event(1))
    r, _ = post_batch(client, [make_event(1), make_event(1)])
    assert r.status_code == 200
    assert all(not it["created"] for it in r.json()["items"])


def test_batch_returns_current_state_for_existing(client):
    post_event(client, make_event(1))
    client.post("/events/evt-0001/ack")
    r, _ = post_batch(client, [make_event(1)])
    assert r.status_code == 200
    item = r.json()["items"][0]
    assert item["created"] is False
    assert item["status"] == "acked"  # 返回库中当前状态，不回退


def test_batch_size_limits(client):
    def raw_post(payload: dict):
        body = json.dumps(payload).encode()
        return client.post("/events/batch", content=body, headers=make_headers(body))

    assert raw_post({"events": []}).status_code == 422
    assert raw_post({"events": [make_event(i) for i in range(101)]}).status_code == 422
    assert raw_post({"events": [make_event(i) for i in range(100)]}).status_code == 201


def test_batch_validation_error(client):
    def raw_post(payload: dict):
        body = json.dumps(payload).encode()
        return client.post("/events/batch", content=body, headers=make_headers(body))

    assert raw_post({}).status_code == 422
    assert raw_post({"events": [{"event_id": "x"}]}).status_code == 422


# ---------- 存储层：并发与持久化 ----------


@pytest.fixture()
def store(tmp_path):
    s = EventStore(Database(str(tmp_path / "store.db")))
    yield s
    s.db.close()


def test_concurrent_duplicates_keep_first_version(store):
    counter = {"n": 0}

    def submit(_):
        counter["n"] += 1
        return store.create_event(
            "evt-x", "t", {"v": "first"}, source="billing", nonce=f"n-{counter['n']}"
        )

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(submit, range(64)))

    assert sum(created for _, created in results) == 1  # 只有一个请求真正写入
    first = results[0][0]
    assert all(rec == first for rec, _ in results)  # 所有结果一致（首个版本）


def test_concurrent_conflicting_content_single_winner(store):
    counter = {"n": 0}

    def submit(i):
        counter["n"] += 1
        try:
            rec, _ = store.create_event(
                "evt-y",
                "t",
                {"v": "a" if i % 2 == 0 else "b"},
                source="billing",
                nonce=f"n-{counter['n']}",
            )
            return ("ok", json.dumps(rec["payload"], sort_keys=True))
        except EventConflictError:
            return ("conflict", None)

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(submit, range(64)))

    winners = {payload for status, payload in results if status == "ok"}
    assert len(winners) == 1  # 并发下只接受了一个版本
    assert any(status == "conflict" for status, _ in results)  # 另一方全部 409
    stored = store.get_event("evt-y")
    assert json.dumps(stored["payload"], sort_keys=True) == next(iter(winners))


def test_persistence_across_reopen(tmp_path):
    path = str(tmp_path / "persist.db")
    s1 = EventStore(Database(path))
    s1.create_event("evt-p", "t", {"k": 1}, source="billing", nonce="n1")
    s1.ack_event("evt-p")
    s1.db.close()

    s2 = EventStore(Database(path))  # 重新打开同一文件
    rec = s2.get_event("evt-p")
    assert rec["status"] == "acked"
    assert rec["acked_at"]
    assert rec["payload"] == {"k": 1}
    # nonce 登记表同样持久化：重放仍被拒绝
    with pytest.raises(NonceReuseError):
        s2.create_event("evt-other", "t", {}, source="billing", nonce="n1")
    s2.db.close()


def test_migrates_legacy_database_without_nonce_table(tmp_path):
    path = str(tmp_path / "legacy.db")
    conn = __import__("sqlite3").connect(path)
    conn.executescript(
        """
        CREATE TABLE events (
          event_id TEXT PRIMARY KEY, type TEXT NOT NULL, payload TEXT NOT NULL,
          content_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
          created_at TEXT NOT NULL, acked_at TEXT
        );
        """
    )
    conn.execute(
        "INSERT INTO events VALUES ('old','t','{}','abc','pending',"
        "'2026-01-01T00:00:00.000000Z',NULL)"
    )
    conn.commit()
    conn.close()

    db = Database(path)  # 启动时 IF NOT EXISTS 自动补表
    names = {
        r[0]
        for r in db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' OR type='index'"
        )
    }
    assert "used_nonces" in names
    assert "idx_used_nonces_expires_at" in names
    row = db.conn.execute("SELECT event_id FROM events WHERE event_id='old'").fetchone()
    assert row is not None  # 既有数据完好
    db.close()


# ---------- 存储层：nonce 登记与重放 ----------


def test_nonce_reuse_store_level_raises(store):
    store.create_event("evt-1", "t", {"v": 1}, source="billing", nonce="dup")
    with pytest.raises(NonceReuseError):
        store.create_event("evt-2", "t", {"v": 2}, source="billing", nonce="dup")
    with pytest.raises(EventNotFoundError):
        store.get_event("evt-2")  # 重放零写入


def test_nonce_scoped_per_source_store_level(store):
    store.create_event("evt-1", "t", {}, source="a", nonce="shared")
    store.create_event("evt-2", "t", {}, source="b", nonce="shared")  # 不同来源不冲突
    assert store.get_event("evt-1")
    assert store.get_event("evt-2")


def test_conflicting_event_rolls_nonce_back(store):
    store.create_event("evt-1", "t", {"v": 1}, source="billing", nonce="n1")
    with pytest.raises(EventConflictError):
        store.create_event("evt-1", "t", {"v": 2}, source="billing", nonce="n2")
    # 409 回滚了整个事务，nonce n2 可被新请求复用
    rec, created = store.create_event("evt-2", "t", {"v": 3}, source="billing", nonce="n2")
    assert created is True
    assert rec["event_id"] == "evt-2"


def test_expired_nonce_is_reusable(store):
    # 直接写入一条已过期的 nonce 记录
    old_seen = (datetime.now(timezone.utc) - timedelta(seconds=700)).strftime(
        "%Y-%m-%dT%H:%M:%S.000000Z"
    )
    old_exp = (datetime.now(timezone.utc) - timedelta(seconds=100)).strftime(
        "%Y-%m-%dT%H:%M:%S.000000Z"
    )
    store.db.lock.acquire()
    try:
        store.db.conn.execute(
            "INSERT INTO used_nonces (source, nonce, seen_at, expires_at) VALUES (?, ?, ?, ?)",
            ("billing", "stale", old_seen, old_exp),
        )
    finally:
        store.db.lock.release()
    # 新请求复用该 nonce：登记时先清理过期记录，插入成功
    rec, created = store.create_event("evt-fresh", "t", {}, source="billing", nonce="stale")
    assert created is True
    remaining = store.db.conn.execute(
        "SELECT COUNT(*) FROM used_nonces WHERE nonce='stale'"
    ).fetchone()[0]
    assert remaining == 1  # 旧记录已被新登记替换


def test_concurrent_replays_single_endpoint_single_winner(store):
    def submit(_):
        try:
            store.create_event("evt-r", "t", {"v": 1}, source="billing", nonce="once")
            return "ok"
        except NonceReuseError:
            return "replay"

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(submit, range(64)))
    assert results.count("ok") == 1
    assert results.count("replay") == 63


def test_concurrent_replays_batch_single_winner(store):
    batch = [("evt-rb1", "t", {"k": 1}), ("evt-rb2", "t", {"k": 2})]

    def submit(_):
        try:
            store.create_events_batch(batch, source="billing", nonce="batch-once")
            return "ok"
        except NonceReuseError:
            return "replay"

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(submit, range(64)))
    assert results.count("ok") == 1
    assert results.count("replay") == 63
    assert store.db.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2
    assert store.db.conn.execute("SELECT COUNT(*) FROM used_nonces").fetchone()[0] == 1


# ---------- 存储层：批量原子性 ----------


def test_store_batch_conflict_rolls_back_everything(store):
    store.create_event("evt-1", "t", {"v": 1}, source="billing", nonce="n1")
    with pytest.raises(BatchConflictError) as exc_info:
        store.create_events_batch(
            [("evt-2", "t", {"v": 2}), ("evt-1", "t", {"v": 9})],
            source="billing",
            nonce="n2",
        )
    assert exc_info.value.event_ids == ["evt-1"]
    with pytest.raises(EventNotFoundError):
        store.get_event("evt-2")  # 整批零写入
    assert store.get_event("evt-1")["payload"] == {"v": 1}
    # 回滚后 nonce n2 未被消费，可被后续合法请求复用
    store.create_event("evt-3", "t", {}, source="billing", nonce="n2")
    assert store.get_event("evt-3")


def test_concurrent_identical_batches_single_created(store):
    counter = {"n": 0}
    batch = [("evt-b1", "t", {"k": 1}), ("evt-b2", "t", {"k": 2})]

    def submit(_):
        counter["n"] += 1
        return store.create_events_batch(batch, source="billing", nonce=f"bn-{counter['n']}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(submit, range(16)))

    for pos in range(2):
        assert sum(created for _, created in (res[pos] for res in outcomes)) == 1
    first_records = [rec for rec, _ in outcomes[0]]
    assert all([rec for rec, _ in res] == first_records for res in outcomes)  # 均为首个版本


def test_concurrent_conflicting_batches_no_partial_commit(store):
    counter = {"n": 0}

    def submit(i):
        counter["n"] += 1
        tag = "a" if i % 2 == 0 else "b"
        try:
            res = store.create_events_batch(
                [("evt-shared", "t", {"v": tag}), (f"evt-uniq-{i}", "t", {"v": i})],
                source="billing",
                nonce=f"cn-{counter['n']}",
            )
            return (tag, res)
        except BatchConflictError:
            return (tag, None)

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(submit, range(32)))

    winner = store.get_event("evt-shared")["payload"]["v"]
    # 与首版内容一致的批次整批成功，其余整批冲突
    assert sum(created for tag, res in results if res for _, created in [res[0]]) == 1
    for i, (tag, res) in enumerate(results):
        if tag == winner:
            assert res is not None
            assert store.get_event(f"evt-uniq-{i}")["payload"] == {"v": i}
        else:
            assert res is None
            with pytest.raises(EventNotFoundError):
                store.get_event(f"evt-uniq-{i}")  # 冲突批次零写入，无部分提交
