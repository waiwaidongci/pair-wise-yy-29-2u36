"""撤销快照持久化：保存签发方发布的撤销名单版本，并提供版本范围查询。"""
from __future__ import annotations

import json
import sqlite3

from credential_utils import iso


class SnapshotStore:
    """revocation_snapshots 表的读写边界，按签发方维护单调递增的版本。"""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.init_schema()

    def init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS revocation_snapshots (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              issuer TEXT NOT NULL,
              version INTEGER NOT NULL,
              key_version INTEGER NOT NULL,
              generated_at TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              entries_json TEXT NOT NULL,
              signature TEXT NOT NULL,
              created_at TEXT NOT NULL,
              UNIQUE(issuer, version)
            );
            """
        )
        self.conn.commit()

    def save(self, *, issuer: str, version: int, key_version: int, generated_at: str, expires_at: str, entries: list[dict], signature: str) -> int:
        cur = self.conn.execute(
            """INSERT INTO revocation_snapshots(issuer,version,key_version,generated_at,expires_at,entries_json,signature,created_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (issuer, version, key_version, generated_at, expires_at, json.dumps(entries, ensure_ascii=False), signature, iso()),
        )
        return cur.lastrowid

    def latest_version(self, issuer: str) -> int | None:
        row = self.conn.execute("SELECT MAX(version) AS v FROM revocation_snapshots WHERE issuer=?", (issuer,)).fetchone()
        return int(row["v"]) if row and row["v"] is not None else None

    def summary(self, at: str) -> list[dict]:
        """按签发方汇总版本范围，并判断最新快照在 at 时刻是否可用。"""
        rows = self.conn.execute(
            """
            SELECT r.issuer AS issuer, r.min_version AS min_version, r.max_version AS latest_version,
                   r.cnt AS count, s.generated_at AS latest_generated_at, s.expires_at AS latest_expires_at
            FROM (SELECT issuer, MIN(version) AS min_version, MAX(version) AS max_version, COUNT(*) AS cnt
                  FROM revocation_snapshots GROUP BY issuer) r
            JOIN revocation_snapshots s ON s.issuer = r.issuer AND s.version = r.max_version
            ORDER BY r.issuer
            """
        ).fetchall()
        return [
            {
                "issuer": row["issuer"],
                "min_version": row["min_version"],
                "latest_version": row["latest_version"],
                "count": row["count"],
                "latest_generated_at": row["latest_generated_at"],
                "latest_expires_at": row["latest_expires_at"],
                "usable_now": row["latest_expires_at"] > at,
            }
            for row in rows
        ]
