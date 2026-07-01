"""SQLite persistence for scan history.

Every completed analysis is recorded so the UI can show trends over time and let
the user revisit past scans. The database is a single project-local file
(``scan_history.db``) — zero external setup, ideal for a self-contained demo.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone

_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scan_history.db")


def _connect(path=_DB_PATH):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path=_DB_PATH):
    """Create the schema if it does not exist. Safe to call repeatedly."""
    with _connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT    NOT NULL,
                source        TEXT    NOT NULL,
                region        TEXT,
                account_id    TEXT,
                total_paths   INTEGER NOT NULL,
                critical      INTEGER NOT NULL DEFAULT 0,
                high          INTEGER NOT NULL DEFAULT 0,
                medium        INTEGER NOT NULL DEFAULT 0,
                low           INTEGER NOT NULL DEFAULT 0,
                max_cvss      REAL    NOT NULL DEFAULT 0,
                nodes         INTEGER NOT NULL DEFAULT 0,
                edges         INTEGER NOT NULL DEFAULT 0,
                report_json   TEXT    NOT NULL
            )
            """
        )
        conn.commit()


def save_scan(result, path=_DB_PATH):
    """Persist an analyzer result dict. Returns the new scan id."""
    init_db(path)
    summary = result.get("summary", {})
    meta = result.get("meta", {})
    stats = result.get("graph_stats", {})
    ts = meta.get("timestamp") or datetime.now(timezone.utc).isoformat()

    with _connect(path) as conn:
        cur = conn.execute(
            """
            INSERT INTO scans (
                timestamp, source, region, account_id, total_paths,
                critical, high, medium, low, max_cvss, nodes, edges, report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts,
                meta.get("source", "unknown"),
                meta.get("region"),
                meta.get("account_id"),
                summary.get("total_paths", 0),
                summary.get("critical", 0),
                summary.get("high", 0),
                summary.get("medium", 0),
                summary.get("low", 0),
                summary.get("max_cvss", 0.0),
                stats.get("nodes", 0),
                stats.get("edges", 0),
                json.dumps(result, default=str),
            ),
        )
        conn.commit()
        return cur.lastrowid


def list_scans(limit=100, path=_DB_PATH):
    """Return recent scans (without the heavy report JSON) as dicts."""
    init_db(path)
    with _connect(path) as conn:
        rows = conn.execute(
            """
            SELECT id, timestamp, source, region, account_id, total_paths,
                   critical, high, medium, low, max_cvss, nodes, edges
            FROM scans ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id, path=_DB_PATH):
    """Return the full stored result dict for a scan id, or None."""
    init_db(path)
    with _connect(path) as conn:
        row = conn.execute(
            "SELECT report_json FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    if not row:
        return None
    return json.loads(row["report_json"])


def delete_scan(scan_id, path=_DB_PATH):
    with _connect(path) as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()


def clear_history(path=_DB_PATH):
    with _connect(path) as conn:
        conn.execute("DELETE FROM scans")
        conn.commit()
