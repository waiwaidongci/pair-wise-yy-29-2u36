"""Revocation snapshot generation (名单生成): issuer-signed, versioned revocation lists."""
from __future__ import annotations

import hashlib
import hmac
from datetime import timedelta

from common import ApiError, canonical, iso, now
from snapshot_store import SnapshotStore, signed_content

DEFAULT_TTL_SECONDS = 24 * 3600
MAX_TTL_SECONDS = 7 * 24 * 3600


class SnapshotPublisher:
    """Builds, signs and persists a new snapshot of an issuer's revoked credentials."""

    def __init__(self, store, snapshots: SnapshotStore):
        self.store = store
        self.conn = store.conn
        self.snapshots = snapshots

    def publish(self, actor: str | None, role: str | None, issuer: str, ttl_seconds: int | None = None) -> dict:
        if not actor:
            raise ApiError(401, "缺少身份")
        if role != "issuer":
            raise ApiError(403, "需要角色 issuer")
        if actor != issuer:
            raise ApiError(403, "只能发布本机构的撤销名单")
        ttl = int(ttl_seconds) if ttl_seconds is not None else DEFAULT_TTL_SECONDS
        if not 60 <= ttl <= MAX_TTL_SECONDS:
            raise ApiError(400, f"快照有效期需在 60 到 {MAX_TTL_SECONDS} 秒之间")
        key = self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND status='active' ORDER BY version DESC LIMIT 1", (issuer,)
        ).fetchone()
        if not key:
            raise ApiError(409, "签发方尚未初始化密钥")
        entries = [
            {
                "credential_id": row["id"],
                "revocation_effective_at": row["revocation_effective_at"],
                "reason": row["revocation_reason"],
            }
            for row in self.conn.execute(
                "SELECT id,revocation_effective_at,revocation_reason FROM credentials WHERE issuer=? AND status='revoked' ORDER BY id",
                (issuer,),
            )
        ]
        generated = now()
        snapshot = {
            "issuer": issuer,
            "version": (self.snapshots.latest_version(issuer) or 0) + 1,
            "generated_at": iso(generated),
            "expires_at": iso(generated + timedelta(seconds=ttl)),
            "key_version": int(key["version"]),
            "entries": entries,
        }
        snapshot["signature"] = hmac.new(
            bytes.fromhex(key["secret_hex"]), canonical(signed_content(snapshot)), hashlib.sha256
        ).hexdigest()
        self.snapshots.save(snapshot)
        with self.conn:
            self.store.audit(
                actor,
                "snapshot.publish",
                "revocation_snapshot",
                f"{issuer}:{snapshot['version']}",
                {"version": snapshot["version"], "entries": len(entries), "expires_at": snapshot["expires_at"]},
            )
        return snapshot
