"""撤销快照生成：签发方把当前已撤销凭证打包成带版本号、生成时间和签名的名单。"""
from __future__ import annotations

import sqlite3
from datetime import timedelta

from credential_utils import ApiError, iso, now, sign_envelope
from snapshot_store import SnapshotStore

MAX_TTL_HOURS = 720  # 快照最长有效期 30 天


class SnapshotPublisher:
    """从凭证表收集已撤销条目，签发自包含的撤销名单令牌并持久化。"""

    def __init__(self, conn: sqlite3.Connection, snapshots: SnapshotStore):
        self.conn = conn
        self.snapshots = snapshots

    def publish(self, issuer: str, ttl_hours: int = 24) -> dict:
        if not 1 <= int(ttl_hours) <= MAX_TTL_HOURS:
            raise ApiError(400, f"快照有效期需在 1 到 {MAX_TTL_HOURS} 小时之间")
        key = self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND status='active' ORDER BY version DESC LIMIT 1", (issuer,)
        ).fetchone()
        if not key:
            raise ApiError(409, "签发方尚未初始化密钥")
        version = (self.snapshots.latest_version(issuer) or 0) + 1
        generated = now()
        expires = generated + timedelta(hours=int(ttl_hours))
        entries = [
            {"credential_id": row["id"], "effective_at": row["revocation_effective_at"], "reason": row["revocation_reason"] or ""}
            for row in self.conn.execute(
                "SELECT id, revocation_effective_at, revocation_reason FROM credentials WHERE issuer=? AND status='revoked' ORDER BY id",
                (issuer,),
            )
        ]
        payload = {
            "issuer": issuer,
            "version": version,
            "generated_at": iso(generated),
            "expires_at": iso(expires),
            "key_version": key["version"],
            "entries": entries,
        }
        token, signature = sign_envelope(payload, key["secret_hex"])
        snapshot_id = self.snapshots.save(
            issuer=issuer,
            version=version,
            key_version=key["version"],
            generated_at=payload["generated_at"],
            expires_at=payload["expires_at"],
            entries=entries,
            signature=signature,
        )
        return {
            "id": snapshot_id,
            "issuer": issuer,
            "version": version,
            "key_version": key["version"],
            "generated_at": payload["generated_at"],
            "expires_at": payload["expires_at"],
            "entries": entries,
            "entries_count": len(entries),
            "signature": signature,
            "token": token,
        }
