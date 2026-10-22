"""SQLite storage: users, jobs, audit log, revoked tokens. Versioned migrations via PRAGMA user_version.

SQLite suits one instance. Multi-instance deployments need Postgres (see README, Scaling).
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable

# Each migration runs once, in order. Append only; never edit a shipped migration.


def _m1_core(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            email                TEXT PRIMARY KEY,
            name                 TEXT NOT NULL DEFAULT '',
            role                 TEXT NOT NULL CHECK (role IN ('admin', 'user')),
            provider             TEXT NOT NULL,
            password_hash        TEXT,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            is_active            INTEGER NOT NULL DEFAULT 1,
            tools                TEXT NOT NULL DEFAULT '[]',
            kind                 TEXT NOT NULL DEFAULT 'human' CHECK (kind IN ('human', 'service')),
            created_at           REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS jobs (
            id          TEXT PRIMARY KEY,
            user_email  TEXT NOT NULL,
            tool        TEXT NOT NULL,
            question    TEXT NOT NULL,
            status      TEXT NOT NULL,
            result      TEXT,
            error       TEXT,
            created_at  REAL NOT NULL,
            updated_at  REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS jobs_user ON jobs (user_email, created_at);
        """
    )
    # Databases created before the kind column existed.
    columns = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "kind" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN kind TEXT NOT NULL DEFAULT 'human'")


def _m2_security(conn: sqlite3.Connection) -> None:
    columns = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "failed_logins" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN failed_logins INTEGER NOT NULL DEFAULT 0")
    if "locked_until" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN locked_until REAL NOT NULL DEFAULT 0")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          REAL NOT NULL,
            request_id  TEXT,
            actor       TEXT,
            action      TEXT NOT NULL,
            target      TEXT,
            outcome     TEXT NOT NULL,
            detail      TEXT
        );
        CREATE INDEX IF NOT EXISTS audit_ts ON audit_log (ts);
        CREATE TABLE IF NOT EXISTS revoked_tokens (
            jti         TEXT PRIMARY KEY,
            expires_at  REAL NOT NULL
        );
        """
    )


def _m3_chats(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS conversations (
            id                     TEXT PRIMARY KEY,
            user_email             TEXT NOT NULL,
            title                  TEXT NOT NULL,
            genie_conversation_id  TEXT,
            created_at             REAL NOT NULL,
            updated_at             REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS conversations_user ON conversations (user_email, updated_at);
        CREATE TABLE IF NOT EXISTS messages (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id  TEXT NOT NULL REFERENCES conversations(id),
            role             TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'summary')),
            content          TEXT NOT NULL,
            job_id           TEXT,
            created_at       REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS messages_conv ON messages (conversation_id, id);
        """
    )
    # Per-job columns. user_token_enc and context_raw are cleared as soon as the job no longer needs them.
    columns = {r[1] for r in conn.execute("PRAGMA table_info(jobs)").fetchall()}
    for name in ("conversation_id", "user_token_enc", "context_raw"):
        if name not in columns:
            conn.execute(f"ALTER TABLE jobs ADD COLUMN {name} TEXT")


def _m4_oauth(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id      TEXT PRIMARY KEY,
            client_name    TEXT NOT NULL DEFAULT '',
            redirect_uris  TEXT NOT NULL,
            created_at     REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS oauth_codes (
            code_hash       TEXT PRIMARY KEY,
            client_id       TEXT NOT NULL,
            user_email      TEXT NOT NULL,
            redirect_uri    TEXT NOT NULL,
            code_challenge  TEXT NOT NULL,
            expires_at      REAL NOT NULL,
            used            INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
            token_hash   TEXT PRIMARY KEY,
            client_id    TEXT NOT NULL,
            user_email   TEXT NOT NULL,
            expires_at   REAL NOT NULL,
            revoked      INTEGER NOT NULL DEFAULT 0
        );
        """
    )


MIGRATIONS: list[Callable[[sqlite3.Connection], None]] = [_m1_core, _m2_security, _m3_chats, _m4_oauth]


class Database:
    def __init__(self, path: str) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            if path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._migrate()

    @property
    def schema_version(self) -> int:
        return int(self._conn.execute("PRAGMA user_version").fetchone()[0])

    def _migrate(self) -> None:
        current = self.schema_version
        for version, migration in enumerate(MIGRATIONS, start=1):
            if version <= current:
                continue
            migration(self._conn)
            self._conn.execute(f"PRAGMA user_version = {version}")
            self._conn.commit()

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        with self._lock:
            self._conn.execute(sql, params)
            self._conn.commit()

    def one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    def many(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def ping(self) -> bool:
        try:
            self.one("SELECT 1 AS ok")
            return True
        except sqlite3.Error:
            return False
