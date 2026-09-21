"""SQLite 连接管理与自动建表。"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id     TEXT PRIMARY KEY,
    type         TEXT NOT NULL,
    payload      TEXT NOT NULL,              -- 规范化后的 JSON 文本
    content_hash TEXT NOT NULL,              -- type + payload 的 SHA-256，用于幂等比对
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'acked')),
    created_at   TEXT NOT NULL,              -- 固定 6 位小数的 UTC ISO-8601
    acked_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events (created_at, event_id);
CREATE INDEX IF NOT EXISTS idx_events_status ON events (status);
"""


class Database:
    """单共享连接 + 可重入锁。

    SQLite 写操作本身串行，锁进一步保证“插入 + 回读”复合操作的原子性，
    使并发重复请求只保留首个版本。WAL 模式提升读写并发。
    """

    def __init__(self, path: str) -> None:
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(SCHEMA)

    @property
    def conn(self) -> sqlite3.Connection:
        return self._conn

    def close(self) -> None:
        with self.lock:
            self._conn.close()
