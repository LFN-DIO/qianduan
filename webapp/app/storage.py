from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from app.config import HISTORY_DB_PATH, MAX_HISTORY_ROWS


def _connect() -> sqlite3.Connection:
    HISTORY_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(HISTORY_DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    return connection


def init_storage() -> None:
    with _connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                filename TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                malicious_probability REAL NOT NULL,
                package_name TEXT,
                size_bytes INTEGER NOT NULL,
                processing_ms INTEGER NOT NULL,
                result_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_analyses_created_at "
            "ON analyses(created_at DESC)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_analyses_sha256 ON analyses(sha256)"
        )


def save_analysis(result: dict) -> None:
    with _connect() as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO analyses (
                id, created_at, filename, sha256, verdict, risk_level,
                malicious_probability, package_name, size_bytes,
                processing_ms, result_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["id"],
                result["created_at"],
                result["file"]["name"],
                result["file"]["sha256"],
                result["verdict"]["code"],
                result["verdict"]["risk_level"],
                result["verdict"]["malicious_probability"],
                result["apk"].get("package_name"),
                result["file"]["size_bytes"],
                result["processing_ms"],
                json.dumps(result, ensure_ascii=False, separators=(",", ":")),
            ),
        )
        connection.execute(
            """
            DELETE FROM analyses
            WHERE id NOT IN (
                SELECT id FROM analyses ORDER BY created_at DESC LIMIT ?
            )
            """,
            (MAX_HISTORY_ROWS,),
        )


def list_analyses(limit: int = 50, query: str = "") -> list[dict]:
    limit = max(1, min(100, limit))
    sql = """
        SELECT id, created_at, filename, sha256, verdict, risk_level,
               malicious_probability, package_name, size_bytes, processing_ms
        FROM analyses
    """
    parameters: list = []
    if query:
        sql += " WHERE filename LIKE ? OR package_name LIKE ? OR sha256 LIKE ?"
        wildcard = f"%{query}%"
        parameters.extend([wildcard, wildcard, wildcard])
    sql += " ORDER BY created_at DESC LIMIT ?"
    parameters.append(limit)

    with _connect() as connection:
        rows = connection.execute(sql, parameters).fetchall()
    return [dict(row) for row in rows]


def get_analysis(analysis_id: str) -> dict | None:
    with _connect() as connection:
        row = connection.execute(
            "SELECT result_json FROM analyses WHERE id = ?", (analysis_id,)
        ).fetchone()
    if not row:
        return None
    return json.loads(row["result_json"])


def delete_analysis(analysis_id: str) -> bool:
    with _connect() as connection:
        cursor = connection.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
    return cursor.rowcount > 0


def history_stats() -> dict:
    with _connect() as connection:
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN verdict = 'malware' THEN 1 ELSE 0 END) AS malware,
                SUM(CASE WHEN verdict = 'benign' THEN 1 ELSE 0 END) AS benign
            FROM analyses
            """
        ).fetchone()
    return {
        "total": int(row["total"] or 0),
        "malware": int(row["malware"] or 0),
        "benign": int(row["benign"] or 0),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

