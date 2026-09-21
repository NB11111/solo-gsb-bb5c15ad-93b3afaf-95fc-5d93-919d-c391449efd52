"""Webhook 来源签名校验与重放防护配置。

入箱请求（POST /events、POST /events/batch）必须携带四个请求头：

- ``X-Webhook-Source``    来源标识，对应 WEBHOOK_SECRETS_JSON 中的键
- ``X-Webhook-Timestamp`` Unix 时间戳（秒），与服务器时间偏差不得超过 300 秒
- ``X-Webhook-Nonce``     一次性随机串，同来源内唯一，重放即 401
- ``X-Webhook-Signature`` HMAC-SHA256(timestamp + "\\n" + nonce + "\\n" + 原始请求体) 的十六进制摘要
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

# 允许的客户端时钟偏移；同时也是 nonce 的最短重放保护窗口
SKEW_SECONDS = 300

SOURCE_HEADER = "x-webhook-source"
TIMESTAMP_HEADER = "x-webhook-timestamp"
NONCE_HEADER = "x-webhook-nonce"
SIGNATURE_HEADER = "x-webhook-signature"

MAX_SOURCE_LEN = 128
MAX_NONCE_LEN = 128
MAX_TIMESTAMP_LEN = 32
MAX_SIGNATURE_LEN = 128  # SHA-256 hex = 64，留有余量


class WebhookAuthError(Exception):
    """请求头 / 时间戳 / 来源 / 签名校验失败，调用方应直接返回 401。"""


@dataclass(frozen=True)
class SourceSecret:
    current: str
    previous: str | None = None
    # previous 密钥仅在该时刻之前可用于验签（宽限期），到期即拒绝
    previous_valid_until: datetime | None = None


def _parse_valid_until(value: object) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("previous_valid_until must be an ISO-8601 timestamp string")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"invalid previous_valid_until: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError("previous_valid_until must include a timezone (e.g. '2026-10-01T00:00:00Z')")
    return parsed.astimezone(timezone.utc)


def load_secrets(raw_env: str | None) -> dict[str, SourceSecret]:
    """解析 WEBHOOK_SECRETS_JSON。

    格式::

        {
          "billing": {
            "current": "<现行密钥>",
            "previous": "<上一密钥，可选>",
            "previous_valid_until": "2026-10-01T00:00:00Z"
          }
        }

    未配置或为空时返回空映射，入箱接口将对所有请求返回 401（默认拒绝）。
    配置非法时抛 ValueError，由启动过程直接失败（fail-fast）。
    """
    if raw_env is None or not raw_env.strip():
        return {}
    try:
        data = json.loads(raw_env)
    except json.JSONDecodeError as exc:
        raise ValueError("WEBHOOK_SECRETS_JSON must be valid JSON") from exc
    if not isinstance(data, dict) or not data:
        raise ValueError("WEBHOOK_SECRETS_JSON must be a non-empty JSON object")

    secrets: dict[str, SourceSecret] = {}
    for source, entry in data.items():
        if not isinstance(source, str) or not source or len(source) > MAX_SOURCE_LEN:
            raise ValueError(f"invalid source name: {source!r}")
        if not isinstance(entry, dict):
            raise ValueError(f"secret entry for {source!r} must be a JSON object")

        current = entry.get("current")
        if not isinstance(current, str) or not current:
            raise ValueError(f"{source!r}: 'current' must be a non-empty string")

        previous = entry.get("previous")
        if previous is not None and (not isinstance(previous, str) or not previous):
            raise ValueError(f"{source!r}: 'previous' must be a non-empty string when present")

        until_raw = entry.get("previous_valid_until")
        valid_until: datetime | None = None
        if previous is not None:
            if until_raw is None:
                raise ValueError(
                    f"{source!r}: 'previous_valid_until' is required when 'previous' is set"
                )
            valid_until = _parse_valid_until(until_raw)
        elif until_raw is not None:
            raise ValueError(f"{source!r}: 'previous' is required when 'previous_valid_until' is set")

        secrets[source] = SourceSecret(current, previous, valid_until)
    return secrets


def signing_message(timestamp: str, nonce: str, body: bytes) -> bytes:
    """固定签名串：timestamp + 换行 + nonce + 换行 + 原始请求体。"""
    return timestamp.encode("utf-8") + b"\n" + nonce.encode("utf-8") + b"\n" + body


def _hex_hmac(secret: str, message: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


class Signer:
    def __init__(self, secrets: dict[str, SourceSecret]) -> None:
        self._secrets = secrets

    def verify(
        self, headers: Any, body: bytes, *, now: datetime | None = None
    ) -> tuple[str, str]:
        """校验请求头与签名，返回 (source, nonce)；失败抛 WebhookAuthError。"""
        source = headers.get(SOURCE_HEADER, "").strip()
        timestamp = headers.get(TIMESTAMP_HEADER, "").strip()
        nonce = headers.get(NONCE_HEADER, "").strip()
        signature = headers.get(SIGNATURE_HEADER, "").strip()

        if not source or not timestamp or not nonce or not signature:
            raise WebhookAuthError(
                "missing required headers: X-Webhook-Source, X-Webhook-Timestamp, "
                "X-Webhook-Nonce, X-Webhook-Signature"
            )
        if (
            len(source) > MAX_SOURCE_LEN
            or len(nonce) > MAX_NONCE_LEN
            or len(timestamp) > MAX_TIMESTAMP_LEN
            or len(signature) > MAX_SIGNATURE_LEN
        ):
            raise WebhookAuthError("webhook header too long")

        try:
            ts = int(timestamp)
        except ValueError:
            raise WebhookAuthError("X-Webhook-Timestamp must be Unix epoch seconds") from None

        now = now or datetime.now(timezone.utc)
        if abs(now.timestamp() - float(ts)) > SKEW_SECONDS:
            raise WebhookAuthError(
                f"X-Webhook-Timestamp deviates more than {SKEW_SECONDS}s from server time"
            )

        secret = self._secrets.get(source)
        if secret is None:
            raise WebhookAuthError("unknown X-Webhook-Source")

        # 签名头只允许 ASCII（hex），避免 compare_digest 对非 ASCII 字符串抛 TypeError
        try:
            signature.encode("ascii")
        except UnicodeEncodeError:
            raise WebhookAuthError("invalid webhook signature") from None

        message = signing_message(timestamp, nonce, body)
        provided = signature.lower()

        # 常量时间比较，先验现行密钥
        if hmac.compare_digest(_hex_hmac(secret.current, message), provided):
            return source, nonce
        # 旧密钥仅在宽限期（previous_valid_until 之前）内接受
        if (
            secret.previous is not None
            and secret.previous_valid_until is not None
            and now < secret.previous_valid_until
            and hmac.compare_digest(_hex_hmac(secret.previous, message), provided)
        ):
            return source, nonce
        raise WebhookAuthError("invalid webhook signature")
