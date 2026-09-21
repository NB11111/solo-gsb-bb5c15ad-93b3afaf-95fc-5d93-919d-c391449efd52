"""事件存取层：幂等写入、时间游标分页、确认。"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .db import Database

STATUS_PENDING = "pending"
STATUS_ACKED = "acked"


class EventConflictError(Exception):
    """event_id 已存在，但提交的内容与首个版本不同。"""

    def __init__(self, event_id: str) -> None:
        super().__init__(event_id)
        self.event_id = event_id


class BatchConflictError(Exception):
    """批量事件与库中已存记录内容冲突（整批未写入）。"""

    def __init__(self, event_ids: list[str]) -> None:
        super().__init__(", ".join(event_ids))
        self.event_ids = event_ids


class EventNotFoundError(Exception):
    pass


class InvalidCursorError(Exception):
    pass


def utcnow_iso() -> str:
    """固定 6 位小数的 UTC ISO-8601 字符串，保证字典序 == 时间序。"""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond:06d}Z"


def canonical_json(value: Any) -> str:
    """规范化 JSON：键排序、无空白，使语义相同的 payload 得到相同文本。"""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_hash(type_: str, payload: Any) -> str:
    return hashlib.sha256(f"{type_}\n{canonical_json(payload)}".encode("utf-8")).hexdigest()


def _row_to_event(row) -> dict:
    return {
        "event_id": row["event_id"],
        "type": row["type"],
        "payload": json.loads(row["payload"]),
        "status": row["status"],
        "created_at": row["created_at"],
        "acked_at": row["acked_at"],
    }


def encode_cursor(created_at: str, event_id: str) -> str:
    raw = json.dumps({"created_at": created_at, "event_id": event_id}, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode()


def decode_cursor(cursor: str) -> tuple[str, str]:
    try:
        data = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        return str(data["created_at"]), str(data["event_id"])
    except Exception as exc:
        raise InvalidCursorError(cursor) from exc


class EventStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create_event(self, event_id: str, type_: str, payload: Any) -> tuple[dict, bool]:
        """幂等写入。

        返回 (事件记录, 是否新建)。并发下由 INSERT OR IGNORE 保证只有首个
        版本落库；重复提交返回库中已存的首个版本；内容不同则抛冲突。
        """
        digest = content_hash(type_, payload)
        created_at = utcnow_iso()
        with self.db.lock:
            cur = self.db.conn.execute(
                """
                INSERT OR IGNORE INTO events
                    (event_id, type, payload, content_hash, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (event_id, type_, canonical_json(payload), digest, STATUS_PENDING, created_at),
            )
            created = cur.rowcount == 1
            row = self.db.conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        if not created and row["content_hash"] != digest:
            raise EventConflictError(event_id)
        return _row_to_event(row), created

    def create_events_batch(self, items: list[tuple[str, str, Any]]) -> list[tuple[dict, bool]]:
        """批量幂等写入：冲突检查与全部插入在单一事务内完成。

        items 需已按 event_id 去重（批内归并在 API 层完成）。任一 event_id
        与库中记录内容冲突则整批零写入并抛 BatchConflictError；否则返回与
        items 顺序对齐的 (事件记录, 是否新建) 列表。连接级锁 + BEGIN IMMEDIATE
        使并发批次彼此串行：要么整批提交，要么整批回滚，不产生部分提交，
        也不会覆盖首个版本。
        """
        if not items:
            return []
        prepared = [
            (event_id, type_, payload, content_hash(type_, payload))
            for event_id, type_, payload in items
        ]
        ids = [event_id for event_id, _, _, _ in prepared]
        placeholders = ", ".join("?" for _ in ids)
        with self.db.lock:
            self.db.conn.execute("BEGIN IMMEDIATE")
            try:
                rows = self.db.conn.execute(
                    f"SELECT * FROM events WHERE event_id IN ({placeholders})", ids
                ).fetchall()
                existing = {row["event_id"]: row for row in rows}
                conflicts = [
                    event_id
                    for event_id, _, _, digest in prepared
                    if event_id in existing and existing[event_id]["content_hash"] != digest
                ]
                if conflicts:
                    raise BatchConflictError(conflicts)
                for event_id, type_, payload, digest in prepared:
                    if event_id in existing:
                        continue
                    self.db.conn.execute(
                        """
                        INSERT INTO events
                            (event_id, type, payload, content_hash, status, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            event_id,
                            type_,
                            canonical_json(payload),
                            digest,
                            STATUS_PENDING,
                            utcnow_iso(),
                        ),
                    )
                rows = self.db.conn.execute(
                    f"SELECT * FROM events WHERE event_id IN ({placeholders})", ids
                ).fetchall()
                self.db.conn.execute("COMMIT")
            except Exception:
                if self.db.conn.in_transaction:
                    self.db.conn.execute("ROLLBACK")
                raise
        by_id = {row["event_id"]: row for row in rows}
        return [
            (_row_to_event(by_id[event_id]), event_id not in existing)
            for event_id, _, _, _ in prepared
        ]

    def get_event(self, event_id: str) -> dict:
        with self.db.lock:
            row = self.db.conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        if row is None:
            raise EventNotFoundError(event_id)
        return _row_to_event(row)

    def list_events(
        self, limit: int, cursor: str | None = None, status: str | None = None
    ) -> dict:
        """按 (created_at, event_id) 升序的键集分页（时间游标）。"""
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if cursor is not None:
            c_created, c_id = decode_cursor(cursor)
            clauses.append("(created_at > ? OR (created_at = ? AND event_id > ?))")
            params.extend([c_created, c_created, c_id])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        # 与批量写入共用一条连接，加锁保证不会读到未提交事务的中间状态
        with self.db.lock:
            rows = self.db.conn.execute(
                f"SELECT * FROM events {where} ORDER BY created_at, event_id LIMIT ?",
                (*params, limit + 1),
            ).fetchall()
        has_more = len(rows) > limit
        items = [_row_to_event(r) for r in rows[:limit]]
        next_cursor = (
            encode_cursor(items[-1]["created_at"], items[-1]["event_id"]) if has_more else None
        )
        return {"items": items, "next_cursor": next_cursor, "has_more": has_more}

    def ack_event(self, event_id: str) -> dict:
        """确认单条事件。幂等：重复确认返回当前状态。"""
        with self.db.lock:
            self.db.conn.execute(
                "UPDATE events SET status = ?, acked_at = ? WHERE event_id = ? AND status = ?",
                (STATUS_ACKED, utcnow_iso(), event_id, STATUS_PENDING),
            )
            row = self.db.conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        if row is None:
            raise EventNotFoundError(event_id)
        return _row_to_event(row)
