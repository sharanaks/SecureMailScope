"""
SQLite database layer for SecureMailScope.

Kept intentionally simple (raw sqlite3, no ORM) so the project is easy
to run and reason about during a 12-hour hackathon.
"""
import sqlite3
import os
import threading
from contextlib import contextmanager

DATABASE_PATH = os.getenv("DATABASE_PATH", "./securemailscope.db")

_local = threading.local()


def get_connection():
    """Return a thread-local SQLite connection."""
    if not hasattr(_local, "conn"):
        _local.conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA foreign_keys = ON")
    return _local.conn


@contextmanager
def get_cursor(commit: bool = False):
    conn = get_connection()
    cur = conn.cursor()
    try:
        yield cur
        if commit:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS assessments (
    id TEXT PRIMARY KEY,               -- assessment UUID
    user_id INTEGER,
    domain TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    score INTEGER NOT NULL,
    raw_findings_json TEXT NOT NULL,   -- JSON list of findings (rule engine output)
    checks_json TEXT NOT NULL,         -- JSON summary of PASS/WARNING/FAIL per check
    ai_explanation_json TEXT,          -- JSON: per-finding explanations + overall summary
    ai_source TEXT,                    -- "llm" or "fallback_template"
    report_json TEXT,                  -- canonical report JSON (frozen at generation time)
    report_hash TEXT,                  -- SHA-256 hex digest of canonical report
    blockchain_status TEXT NOT NULL DEFAULT 'not_anchored', -- not_anchored | anchored | failed
    blockchain_tx_hash TEXT,
    blockchain_timestamp TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
"""


def init_db():
    with get_cursor(commit=True) as cur:
        cur.executescript(SCHEMA)
