"""Webhook 收件箱 API。"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from .db import Database
from .store import (
    BatchConflictError,
    EventConflictError,
    EventNotFoundError,
    EventStore,
    InvalidCursorError,
    content_hash,
)


class EventIn(BaseModel):
    event_id: str = Field(min_length=1, max_length=128)
    type: str = Field(min_length=1, max_length=128)
    payload: Any


class EventOut(BaseModel):
    event_id: str
    type: str
    payload: Any
    status: Literal["pending", "acked"]
    created_at: str
    acked_at: str | None = None


class EventPage(BaseModel):
    items: list[EventOut]
    next_cursor: str | None
    has_more: bool


class EventBatchIn(BaseModel):
    events: list[EventIn] = Field(min_length=1, max_length=100)


class BatchItemOut(EventOut):
    created: bool


class EventBatchOut(BaseModel):
    items: list[BatchItemOut]


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时自动建表（CREATE TABLE IF NOT EXISTS）
    db = Database(os.environ.get("DATABASE_PATH", "events.db"))
    app.state.store = EventStore(db)
    yield
    db.close()


app = FastAPI(title="Webhook Inbox", version="1.0.0", lifespan=lifespan)


def get_store(request: Request) -> EventStore:
    return request.app.state.store


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/events", response_model=EventOut, status_code=201)
def create_event(event: EventIn, response: Response, store: EventStore = Depends(get_store)):
    """提交事件。重复提交（内容相同）返回 200 与首个版本；内容不同返回 409。"""
    try:
        record, created = store.create_event(event.event_id, event.type, event.payload)
    except EventConflictError as exc:
        raise HTTPException(
            status_code=409,
            detail=f"event_id '{exc.event_id}' already exists with different content",
        )
    response.status_code = 201 if created else 200
    return record


@app.post("/events/batch", response_model=EventBatchOut, status_code=201)
def create_events_batch(
    batch: EventBatchIn, response: Response, store: EventStore = Depends(get_store)
):
    """批量提交事件（1~100 个），整批原子写入。

    批内同 event_id 且内容语义相同视为重复，映射到同一结果；同 ID 内容不同
    返回 422 并标出冲突下标。与库中记录内容冲突返回 409 及对应下标，且整批
    零写入。无冲突时单事务写入全部新事件，按原输入顺序返回记录与 created
    标记；全部已存在时返回 200，否则 201。
    """
    # 批内按 event_id 归并：分组 + 语义级内容比对（与单条接口同一套指纹）
    groups: dict[str, list[int]] = {}
    for idx, event in enumerate(batch.events):
        groups.setdefault(event.event_id, []).append(idx)

    intra_conflicts = []
    unique_items: list[tuple[str, str, Any]] = []
    unique_pos: dict[str, int] = {}
    for event_id, indices in groups.items():
        first = batch.events[indices[0]]
        digest = content_hash(first.type, first.payload)
        if any(
            content_hash(batch.events[i].type, batch.events[i].payload) != digest
            for i in indices[1:]
        ):
            intra_conflicts.append({"event_id": event_id, "indices": indices})
        else:
            unique_pos[event_id] = len(unique_items)
            unique_items.append((event_id, first.type, first.payload))
    if intra_conflicts:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "duplicate event_id with different content in batch",
                "conflicts": intra_conflicts,
            },
        )

    try:
        results = store.create_events_batch(unique_items)
    except BatchConflictError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "events already exist with different content",
                "conflicts": [
                    {"event_id": event_id, "indices": groups[event_id]}
                    for event_id in exc.event_ids
                ],
            },
        )

    items = []
    any_created = False
    for event in batch.events:
        record, created = results[unique_pos[event.event_id]]
        any_created = any_created or created
        items.append({**record, "created": created})
    if not any_created:
        response.status_code = 200
    return {"items": items}


@app.get("/events", response_model=EventPage)
def list_events(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
    status: Literal["pending", "acked"] | None = Query(default=None),
    store: EventStore = Depends(get_store),
):
    """按时间游标分页查询事件（升序）。"""
    try:
        return store.list_events(limit=limit, cursor=cursor, status=status)
    except InvalidCursorError:
        raise HTTPException(status_code=400, detail="invalid cursor")


@app.get("/events/{event_id}", response_model=EventOut)
def get_event(event_id: str, store: EventStore = Depends(get_store)):
    try:
        return store.get_event(event_id)
    except EventNotFoundError:
        raise HTTPException(status_code=404, detail="event not found")


@app.post("/events/{event_id}/ack", response_model=EventOut)
def ack_event(event_id: str, store: EventStore = Depends(get_store)):
    """确认单条事件（幂等）。"""
    try:
        return store.ack_event(event_id)
    except EventNotFoundError:
        raise HTTPException(status_code=404, detail="event not found")
