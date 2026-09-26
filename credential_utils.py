"""共享工具：时间格式、规范化 JSON 编码、HMAC 签名信封与 API 错误。"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or now()).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value: str | None) -> datetime:
    if not value:
        return now()
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def sign_envelope(payload: dict, secret_hex: str) -> tuple[str, str]:
    """返回 (令牌, 签名)，令牌为 base64url 编码的 {payload, signature} 信封。"""
    signature = hmac.new(bytes.fromhex(secret_hex), canonical(payload), hashlib.sha256).hexdigest()
    token = base64.urlsafe_b64encode(canonical({"payload": payload, "signature": signature})).decode().rstrip("=")
    return token, signature


def read_envelope(token: str) -> tuple[dict, str]:
    """解析签名信封，返回 (payload, signature)；格式错误抛出 ValueError。"""
    if not isinstance(token, str):
        raise ValueError("签名信封格式错误")
    try:
        padded = token + "=" * (-len(token) % 4)
        envelope = json.loads(base64.urlsafe_b64decode(padded.encode()))
        payload = envelope["payload"]
        signature = envelope["signature"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError("签名信封格式错误") from exc
    if not isinstance(payload, dict) or not isinstance(signature, str):
        raise ValueError("签名信封格式错误")
    return payload, signature
