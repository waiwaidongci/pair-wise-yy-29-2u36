"""Persistence for signed revocation snapshots (撤销名单快照的持久化)."""
from __future__ import annotations

import json
import sqlite3

from common import ApiError, iso, now, parse_time

SNAPSHOT_FIELDS = ("issuer", "version", "generated_at", "expires_at", "key_version", "entries")


def signed_content(snapshot: dict) -> dict:
    """The canonical fields covered by the issuer signature."""
    return {field: snapshot[field] for field in SNAPSHOT_FIELDS}


class SnapshotStore:
    """Owns the revocation_snapshots table; shared by the publisher and the verifier."""

    def __init__(self, store):
        self.store = store
        self.conn = store.conn
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS revocation_snapshots (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              issuer TEXT NOT NULL,
              version INTEGER NOT NULL,
              generated_at TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              key_version INTEGER NOT NULL,
              entries_json TEXT NOT NULL,
              signature TEXT NOT NULL,
              created_at TEXT NOT NULL,
              UNIQUE(issuer, version)
            );
            """
        )
        self.conn.commit()

    def save(self, snapshot: dict) -> None:
        try:
            with self.conn:
                self.conn.execute(
                    """INSERT INTO revocation_snapshots(issuer,version,generated_at,expires_at,key_version,entries_json,signature,created_at)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (
                        snapshot["issuer"],
                        int(snapshot["version"]),
                        snapshot["generated_at"],
                        snapshot["expires_at"],
                        int(snapshot["key_version"]),
                        json.dumps(snapshot["entries"], ensure_ascii=False),
                        snapshot["signature"],
                        iso(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "快照版本已存在，请重新生成") from exc

    def latest_version(self, issuer: str) -> int | None:
        row = self.conn.execute("SELECT MAX(version) AS v FROM revocation_snapshots WHERE issuer=?", (issuer,)).fetchone()
        return int(row["v"]) if row and row["v"] is not None else None

    def get(self, issuer: str, version: int) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM revocation_snapshots WHERE issuer=? AND version=?", (issuer, int(version))
        ).fetchone()
        return self._dict(row) if row else None

    def status(self) -> list[dict]:
        """Per-issuer version range and whether the latest snapshot is usable right now."""
        moment = now()
        rows = self.conn.execute(
            """SELECT issuer, MIN(version) AS min_v, MAX(version) AS max_v, COUNT(*) AS total
               FROM revocation_snapshots GROUP BY issuer ORDER BY issuer"""
        ).fetchall()
        status = []
        for row in rows:
            latest = self.get(row["issuer"], int(row["max_v"]))
            status.append(
                {
                    "issuer": row["issuer"],
                    "min_version": int(row["min_v"]),
                    "max_version": int(row["max_v"]),
                    "snapshot_count": int(row["total"]),
                    "latest_generated_at": latest["generated_at"],
                    "latest_expires_at": latest["expires_at"],
                    "latest_entries": len(latest["entries"]),
                    "usable_now": parse_time(latest["expires_at"]) > moment,
                }
            )
        return status

    def _dict(self, row: sqlite3.Row) -> dict:
        return {
            "issuer": row["issuer"],
            "version": int(row["version"]),
            "generated_at": row["generated_at"],
            "expires_at": row["expires_at"],
            "key_version": int(row["key_version"]),
            "entries": json.loads(row["entries_json"]),
            "signature": row["signature"],
        }
