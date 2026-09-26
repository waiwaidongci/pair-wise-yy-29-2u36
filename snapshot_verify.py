"""撤销快照核验判定：断网场景下用签名快照判定凭证撤销状态。

快照过期、版本倒退或签名不符时不出具有效结论，结论停留在待联网复核。
"""
from __future__ import annotations

import hashlib
import hmac
import sqlite3
from datetime import datetime

from credential_utils import canonical, parse_time, read_envelope
from snapshot_store import SnapshotStore

PENDING = "pending_online"


class SnapshotVerifier:
    """对照快照令牌与本地已知最新版本，给出 valid / revoked / pending 判定。"""

    def __init__(self, conn: sqlite3.Connection, snapshots: SnapshotStore):
        self.conn = conn
        self.snapshots = snapshots

    def judge(self, credential: sqlite3.Row, snapshot_token: str, check_at: datetime) -> dict:
        meta: dict = {"status": "malformed"}
        try:
            payload, signature = read_envelope(snapshot_token)
        except ValueError:
            return self._pending(meta, "撤销快照无法解析，需联网复核")
        meta = {
            "issuer": payload.get("issuer"),
            "version": payload.get("version"),
            "generated_at": payload.get("generated_at"),
            "expires_at": payload.get("expires_at"),
            "status": "malformed",
        }
        required = ("issuer", "version", "generated_at", "expires_at", "key_version", "entries")
        if (
            any(field not in payload for field in required)
            or not isinstance(payload["entries"], list)
            or not isinstance(payload["version"], int)
            or not isinstance(payload["key_version"], int)
        ):
            return self._pending(meta, "撤销快照内容不完整，需联网复核")
        if payload["issuer"] != credential["issuer"]:
            meta["status"] = "issuer_mismatch"
            return self._pending(meta, "撤销快照签发方与凭证签发方不符，需联网复核")
        key = self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND version=?", (payload["issuer"], payload["key_version"])
        ).fetchone()
        if not key:
            meta["status"] = "key_missing"
            return self._pending(meta, "找不到撤销快照的签名密钥，需联网复核")
        expected = hmac.new(bytes.fromhex(key["secret_hex"]), canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            meta["status"] = "signature_invalid"
            return self._pending(meta, "撤销快照签名不符，需联网复核")
        try:
            expires_at = parse_time(payload["expires_at"])
            parse_time(payload["generated_at"])
        except ValueError:
            return self._pending(meta, "撤销快照时间字段无效，需联网复核")
        if check_at >= expires_at:
            meta["status"] = "expired"
            return self._pending(meta, f"撤销快照已过期（过期时间 {payload['expires_at']}），需联网复核")
        latest = self.snapshots.latest_version(payload["issuer"])
        if latest is not None and payload["version"] < latest:
            meta["status"] = "version_regressed"
            return self._pending(meta, f"撤销快照版本倒退（快照 v{payload['version']}，已知最新 v{latest}），需联网复核")
        meta["status"] = "ok"
        return self._conclusion(credential, payload, meta, check_at)

    def _conclusion(self, credential: sqlite3.Row, payload: dict, meta: dict, check_at: datetime) -> dict:
        for entry in payload["entries"]:
            if not isinstance(entry, dict) or entry.get("credential_id") != credential["id"]:
                continue
            effective_raw = entry.get("effective_at")
            if not isinstance(effective_raw, str):
                return self._pending({**meta, "status": "malformed"}, "撤销快照条目缺少生效时刻，需联网复核")
            try:
                effective = parse_time(effective_raw)
            except ValueError:
                return self._pending({**meta, "status": "malformed"}, "撤销快照条目时间无效，需联网复核")
            if check_at >= effective:
                return {
                    "valid": False,
                    "status": "revoked",
                    "reason": entry.get("reason") or "凭证已被签发方撤销",
                    "revocation_effective_at": effective_raw,
                    "snapshot": meta,
                    "revocation_freshness": "snapshot",
                }
            return {
                "valid": True,
                "status": "valid_until_revocation",
                "revocation_starts_at": effective_raw,
                "snapshot": meta,
                "revocation_freshness": "snapshot",
            }
        return {"valid": True, "status": "valid_offline", "snapshot": meta, "revocation_freshness": "snapshot"}

    @staticmethod
    def _pending(meta: dict, reason: str) -> dict:
        return {"valid": None, "status": PENDING, "reason": reason, "snapshot": meta, "revocation_freshness": "needs_online_check"}
