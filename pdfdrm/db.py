"""SQLite-Datenhaltung (stdlib, keine ORM-Abhängigkeit)."""

from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name            TEXT NOT NULL DEFAULT '',
    password_hash   TEXT NOT NULL,
    active          INTEGER NOT NULL DEFAULT 1,
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    REAL NOT NULL DEFAULT 0,
    created_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS documents (
    id              TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    filename        TEXT NOT NULL,
    page_count      INTEGER NOT NULL,
    size_bytes      INTEGER NOT NULL,
    sha256          TEXT NOT NULL,
    wrapped_key     BLOB NOT NULL,
    created_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS licenses (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    document_id     TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    valid_from      REAL,
    valid_until     REAL,
    max_devices     INTEGER,
    max_opens       INTEGER,
    open_count      INTEGER NOT NULL DEFAULT 0,
    allow_print     INTEGER NOT NULL DEFAULT 0,
    allow_download  INTEGER NOT NULL DEFAULT 0,
    watermark_text  TEXT,
    revoked         INTEGER NOT NULL DEFAULT 0,
    revoked_at      REAL,
    created_at      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_licenses_user ON licenses(user_id);

CREATE TABLE IF NOT EXISTS license_devices (
    license_id      TEXT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    device_id       TEXT NOT NULL,
    first_seen      REAL NOT NULL,
    last_seen       REAL NOT NULL,
    PRIMARY KEY (license_id, device_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL NOT NULL,
    event           TEXT NOT NULL,
    user_id         TEXT,
    document_id     TEXT,
    license_id      TEXT,
    device_id       TEXT,
    ip              TEXT,
    detail          TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""


def new_id() -> str:
    return uuid.uuid4().hex


class Database:
    """Dünner, threadsicherer Wrapper um eine SQLite-Verbindung."""

    def __init__(self, path: Path | str):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._lock = threading.RLock()
        self._conn.executescript(SCHEMA)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def execute(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def one(self, sql: str, params: tuple | dict = ()) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    def all(self, sql: str, params: tuple | dict = ()) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def audit(
        self,
        event: str,
        *,
        user_id: str | None = None,
        document_id: str | None = None,
        license_id: str | None = None,
        device_id: str | None = None,
        ip: str | None = None,
        detail: str | None = None,
    ) -> None:
        self.execute(
            "INSERT INTO audit_log (ts, event, user_id, document_id, license_id, device_id, ip, detail)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time(), event, user_id, document_id, license_id, device_id, ip, detail),
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()
