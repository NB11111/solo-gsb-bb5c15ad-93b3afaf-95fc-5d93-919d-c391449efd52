import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app.db import Database
from app.main import app
from app.store import (
    BatchConflictError,
    EventConflictError,
    EventNotFoundError,
    EventStore,
)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def store(tmp_path):
    s = EventStore(Database(str(tmp_path / "store.db")))
    yield s
    s.db.close()


def make_event(i: int) -> dict:
    return {"event_id": f"evt-{i:04d}", "type": "user.created", "payload": {"n": i}}


# ---------- API 层 ----------


def test_create_event_returns_201(client):
    r = client.post("/events", json=make_event(1))
    assert r.status_code == 201
    body = r.json()
    assert body["event_id"] == "evt-0001"
    assert body["type"] == "user.created"
    assert body["payload"] == {"n": 1}
    assert body["status"] == "pending"
    assert body["acked_at"] is None
    assert body["created_at"]


def test_duplicate_same_content_returns_consistent_result(client):
    first = client.post("/events", json=make_event(1))
    dup = client.post("/events", json=make_event(1))
    assert first.status_code == 201
    assert dup.status_code == 200
    assert dup.json() == first.json()  # 返回与首个版本一致的结果


def test_duplicate_is_semantic_not_textual(client):
    client.post("/events", json={"event_id": "e1", "type": "t", "payload": {"a": 1, "b": 2}})
    r = client.post("/events", json={"event_id": "e1", "type": "t", "payload": {"b": 2, "a": 1}})
    assert r.status_code == 200  # 键序不同但语义相同，不算冲突


def test_same_id_different_content_returns_409(client):
    client.post("/events", json=make_event(1))
    r = client.post(
        "/events", json={"event_id": "evt-0001", "type": "user.created", "payload": {"n": 999}}
    )
    assert r.status_code == 409
    r2 = client.post(
        "/events", json={"event_id": "evt-0001", "type": "other.type", "payload": {"n": 1}}
    )
    assert r2.status_code == 409
    # 冲突写入不会覆盖首个版本
    assert client.get("/events/evt-0001").json()["payload"] == {"n": 1}


def test_validation_error(client):
    assert client.post("/events", json={"event_id": "x"}).status_code == 422
    assert client.post("/events", json={"event_id": "", "type": "t", "payload": {}}).status_code == 422


def test_get_single_event(client):
    client.post("/events", json=make_event(1))
    r = client.get("/events/evt-0001")
    assert r.status_code == 200
    assert r.json()["event_id"] == "evt-0001"
    assert client.get("/events/nope").status_code == 404


def test_pagination_walks_all_events_in_order(client):
    for i in range(25):
        client.post("/events", json=make_event(i))

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
        client.post("/events", json=make_event(i))
    client.post("/events/evt-0001/ack")
    client.post("/events/evt-0003/ack")

    pending = client.get("/events", params={"status": "pending"}).json()
    acked = client.get("/events", params={"status": "acked"}).json()
    assert len(pending["items"]) == 3
    assert len(acked["items"]) == 2
    assert {i["event_id"] for i in acked["items"]} == {"evt-0001", "evt-0003"}


def test_ack_event(client):
    client.post("/events", json=make_event(1))
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


# ---------- 批量接口 ----------


def test_batch_create_all_new(client):
    events = [make_event(i) for i in range(3)]
    r = client.post("/events/batch", json={"events": events})
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
    r = client.post("/events/batch", json={"events": events})
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
    r = client.post("/events/batch", json={"events": events})
    assert r.status_code == 422
    assert r.json()["detail"]["conflicts"] == [{"event_id": "e1", "indices": [0, 2]}]
    assert client.get("/events").json()["items"] == []  # 整批零写入


def test_batch_db_conflict_returns_409_and_zero_writes(client):
    client.post("/events", json={"event_id": "e1", "type": "t", "payload": {"v": 1}})
    events = [
        {"event_id": "e2", "type": "t", "payload": {"v": 2}},
        {"event_id": "e1", "type": "t", "payload": {"v": 999}},  # 与库中首版冲突
    ]
    r = client.post("/events/batch", json={"events": events})
    assert r.status_code == 409
    assert r.json()["detail"]["conflicts"] == [{"event_id": "e1", "indices": [1]}]
    assert client.get("/events/e2").status_code == 404  # 整批零写入
    assert client.get("/events/e1").json()["payload"] == {"v": 1}  # 首版未被覆盖


def test_batch_db_conflict_reports_all_indices_of_duplicates(client):
    client.post("/events", json={"event_id": "e1", "type": "t", "payload": {"v": 1}})
    dup = {"event_id": "e1", "type": "t", "payload": {"v": 2}}
    r = client.post("/events/batch", json={"events": [dup, make_event(5), dup]})
    assert r.status_code == 409
    assert r.json()["detail"]["conflicts"] == [{"event_id": "e1", "indices": [0, 2]}]
    assert client.get("/events/evt-0005").status_code == 404


def test_batch_existing_same_content_marked_not_created(client):
    first = client.post("/events", json=make_event(1)).json()
    r = client.post("/events/batch", json={"events": [make_event(1), make_event(2)]})
    assert r.status_code == 201  # 含有新事件
    items = r.json()["items"]
    assert items[0]["created"] is False
    assert items[0]["created_at"] == first["created_at"]  # 返回库中首个版本
    assert items[1]["created"] is True


def test_batch_all_duplicates_returns_200(client):
    client.post("/events", json=make_event(1))
    r = client.post("/events/batch", json={"events": [make_event(1), make_event(1)]})
    assert r.status_code == 200
    assert all(not it["created"] for it in r.json()["items"])


def test_batch_returns_current_state_for_existing(client):
    client.post("/events", json=make_event(1))
    client.post("/events/evt-0001/ack")
    r = client.post("/events/batch", json={"events": [make_event(1)]})
    assert r.status_code == 200
    item = r.json()["items"][0]
    assert item["created"] is False
    assert item["status"] == "acked"  # 返回库中当前状态，不回退


def test_batch_size_limits(client):
    assert client.post("/events/batch", json={"events": []}).status_code == 422
    too_many = {"events": [make_event(i) for i in range(101)]}
    assert client.post("/events/batch", json=too_many).status_code == 422
    exactly_max = {"events": [make_event(i) for i in range(100)]}
    assert client.post("/events/batch", json=exactly_max).status_code == 201


def test_batch_validation_error(client):
    assert client.post("/events/batch", json={}).status_code == 422
    assert client.post("/events/batch", json={"events": [{"event_id": "x"}]}).status_code == 422


# ---------- 存储层：并发与持久化 ----------


def test_concurrent_duplicates_keep_first_version(store):
    def submit(_):
        return store.create_event("evt-x", "t", {"v": "first"})

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(submit, range(64)))

    assert sum(created for _, created in results) == 1  # 只有一个请求真正写入
    first = results[0][0]
    assert all(rec == first for rec, _ in results)  # 所有结果一致（首个版本）


def test_concurrent_conflicting_content_single_winner(store):
    def submit(i):
        try:
            rec, _ = store.create_event("evt-y", "t", {"v": "a" if i % 2 == 0 else "b"})
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
    s1.create_event("evt-p", "t", {"k": 1})
    s1.ack_event("evt-p")
    s1.db.close()

    s2 = EventStore(Database(path))  # 重新打开同一文件
    rec = s2.get_event("evt-p")
    assert rec["status"] == "acked"
    assert rec["acked_at"]
    assert rec["payload"] == {"k": 1}
    s2.db.close()


# ---------- 存储层：批量原子性 ----------


def test_store_batch_conflict_rolls_back_everything(store):
    store.create_event("evt-1", "t", {"v": 1})
    with pytest.raises(BatchConflictError) as exc_info:
        store.create_events_batch([("evt-2", "t", {"v": 2}), ("evt-1", "t", {"v": 9})])
    assert exc_info.value.event_ids == ["evt-1"]
    with pytest.raises(EventNotFoundError):
        store.get_event("evt-2")  # 整批零写入
    assert store.get_event("evt-1")["payload"] == {"v": 1}


def test_concurrent_identical_batches_single_created(store):
    batch = [("evt-b1", "t", {"k": 1}), ("evt-b2", "t", {"k": 2})]

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: store.create_events_batch(batch), range(16)))

    for pos in range(2):
        assert sum(created for _, created in (res[pos] for res in outcomes)) == 1
    first_records = [rec for rec, _ in outcomes[0]]
    assert all([rec for rec, _ in res] == first_records for res in outcomes)  # 均为首个版本


def test_concurrent_conflicting_batches_no_partial_commit(store):
    def submit(i):
        tag = "a" if i % 2 == 0 else "b"
        try:
            res = store.create_events_batch(
                [("evt-shared", "t", {"v": tag}), (f"evt-uniq-{i}", "t", {"v": i})]
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
