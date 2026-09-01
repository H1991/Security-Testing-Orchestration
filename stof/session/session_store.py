"""Layer 5 — in-memory + SQLite session store.

Persists one Session per role to SQLite (mirrors Layer 2's Job
checkpointing -- same `data/stof.db`), so a crash-and-resume can reuse
still-valid sessions instead of re-authenticating every role from
scratch.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from stof.core.logger import get_logger

from .models import Session

_log = get_logger("session.session_store")

DEFAULT_DB_PATH = Path("data/stof.db")


class SessionStore:
    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    role TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    auth_type TEXT NOT NULL,
                    cookies TEXT NOT NULL,
                    headers TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    is_valid INTEGER NOT NULL
                )
                """
            )

    def save(self, session: Session) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO sessions (role, session_id, user_id, auth_type, cookies, headers,
                                       created_at, expires_at, is_valid)
                VALUES (:role, :session_id, :user_id, :auth_type, :cookies, :headers,
                        :created_at, :expires_at, :is_valid)
                ON CONFLICT(role) DO UPDATE SET
                    session_id=excluded.session_id,
                    user_id=excluded.user_id,
                    auth_type=excluded.auth_type,
                    cookies=excluded.cookies,
                    headers=excluded.headers,
                    created_at=excluded.created_at,
                    expires_at=excluded.expires_at,
                    is_valid=excluded.is_valid
                """,
                session.to_row(),
            )

    def load(self, role: str) -> Session | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE role = ?", (role,)).fetchone()
        return Session.from_row(dict(row)) if row else None

    def load_all(self) -> dict[str, Session]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM sessions").fetchall()
        return {row["role"]: Session.from_row(dict(row)) for row in rows}

    def delete(self, role: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE role = ?", (role,))
