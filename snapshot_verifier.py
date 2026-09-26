"""Offline verification decisions against a presented revocation snapshot (核验判定).

断网考点核验时携带快照与核验时刻：快照过期、版本倒退或签名不符一律停在
pending_online（待联网复核），不给出有效结论；名单覆盖到的已撤销凭证按
revocation_effective_at 生效时刻拒绝。
"""
from __future__ import annotations

import hashlib
import hmac

from common import ApiError, canonical, parse_time
from snapshot_store import SnapshotStore, signed_content

PENDING_STATUS = "pending_online"
REQUIRED_FIELDS = ("issuer", "version", "generated_at", "expires_at", "key_version", "entries", "signature")


class SnapshotVerifier:
    """Decides credential validity from a presented snapshot instead of the live revocation table."""

    def __init__(self, service, snapshots: SnapshotStore):
        self.service = service
        self.conn = service.conn
        self.snapshots = snapshots

    def verify(self, token: str, snapshot: dict, at: str | None = None) -> dict:
        payload, credential, key = self.service.authenticate_token(token)
        check_at = parse_time(at)
        problem = self._snapshot_problem(snapshot, credential, check_at)
        if problem:
            return {
                "valid": None,
                "status": PENDING_STATUS,
                "reason": problem,
                "offline": True,
                "snapshot_version": snapshot["version"],
                "claims": payload.get("claims", {}),
            }
        entries = {int(entry["credential_id"]): entry for entry in snapshot["entries"]}
        result = {
            "valid": True,
            "status": "valid_snapshot",
            "offline": True,
            "revocation_freshness": "snapshot",
            "snapshot_version": int(snapshot["version"]),
            "snapshot_generated_at": snapshot["generated_at"],
            "snapshot_expires_at": snapshot["expires_at"],
            "key_retired": key["status"] == "retired",
            "claims": payload.get("claims", {}),
        }
        if check_at >= parse_time(credential["valid_until"]):
            result.update(valid=False, status="expired", reason="凭证已过期")
            return result
        entry = entries.get(int(credential["id"]))
        if entry:
            effective = parse_time(entry["revocation_effective_at"])
            if check_at >= effective:
                result.update(
                    valid=False,
                    status="revoked",
                    reason=entry.get("reason") or "凭证已被撤销",
                    revocation_effective_at=entry["revocation_effective_at"],
                )
            else:
                result.update(status="valid_until_revocation", revocation_starts_at=entry["revocation_effective_at"])
        return result

    def _snapshot_problem(self, snapshot: dict, credential, check_at) -> str | None:
        """Return why the snapshot cannot support a conclusion, or None if it is usable."""
        if not isinstance(snapshot, dict) or any(field not in snapshot for field in REQUIRED_FIELDS):
            raise ApiError(400, "撤销快照格式错误")
        try:
            version = int(snapshot["version"])
            key_version = int(snapshot["key_version"])
            expires_at = parse_time(str(snapshot["expires_at"]))
            parse_time(str(snapshot["generated_at"]))
            if not isinstance(snapshot["entries"], list):
                raise ValueError("entries")
            for entry in snapshot["entries"]:
                int(entry["credential_id"])
                parse_time(str(entry["revocation_effective_at"]))
        except (TypeError, ValueError, KeyError) as exc:
            raise ApiError(400, "撤销快照格式错误") from exc
        if str(snapshot["issuer"]) != credential["issuer"]:
            return "快照签发方与凭证签发方不一致"
        key = self.conn.execute(
            "SELECT * FROM key_versions WHERE issuer=? AND version=?", (snapshot["issuer"], key_version)
        ).fetchone()
        if not key:
            return "快照签名密钥缺失"
        expected = hmac.new(bytes.fromhex(key["secret_hex"]), canonical(signed_content(snapshot)), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(snapshot["signature"])):
            return "快照签名无效"
        latest = self.snapshots.latest_version(str(snapshot["issuer"]))
        if latest is not None and version < latest:
            return f"快照版本倒退，本地已到 v{latest}"
        if check_at > expires_at:
            return "快照已过期"
        return None
