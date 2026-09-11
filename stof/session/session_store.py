"""Layer 5 — in-memory + SQLite session store.

Persists one Session per (role, target) to SQLite (mirrors Layer 2's
Job checkpointing -- same `data/stof.db`), so a crash-and-resume can
reuse still-valid sessions instead of re-authenticating every role
from scratch.

Real bug this closes, live-confirmed this session: the table used to
be keyed by `role` ALONE. Two scans running concurrently against
DIFFERENT targets but sharing a role name (the common case -- "admin"/
"normal" are this project's own default role names in every sample
config) shared the exact same row. A scan against target B's "admin"
role would load target A's still-unexpired "admin" session straight
out of the shared table at `SessionManager.__init__` time and reuse
its cookies/headers verbatim, no re-authentication, no target check.
Caught live: running a demo.testfire.net scan and a Juice Shop scan in
parallel produced a Juice Shop request carrying demo.testfire.net's
own `AltoroAccounts` cookie. `target` (the scan's `config.target.
base_url`) is now part of the row's real key, so two scans against
different targets can never collide, while a *resumed* scan against
the *same* target still finds and reuses its own prior session exactly
as before.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from stof.core.logger import get_logger

from .models import Session

_log = get_logger("session.session_store")

DEFAULT_DB_PATH = Path("data/stof.db")


class SessionStore:
    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH, target: str = "") -> None:
        self.db_path = Path(db_path)
        # "" (the default) matches every pre-existing call site that
        # doesn't pass a target -- those callers (mostly tests) get the
        # single-scan behavior this store always had; a real scan
        # (`main.py`) always passes the real `config.target.base_url`.
        self._target = target
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(sessions)")}
            if cols and "target" not in cols:
                # Pre-existing table from before per-target scoping
                # existed -- `role` alone was PRIMARY KEY, exactly the
                # cross-target collision this migration fixes (see this
                # module's own docstring). Safe to drop: this table is
                # a session CACHE, never a source of truth -- the worst
                # case after this migration is one extra
                # re-authentication per role the next time it's used.
                conn.execute("DROP TABLE sessions")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    role TEXT NOT NULL,
                    target TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    auth_type TEXT NOT NULL,
                    cookies TEXT NOT NULL,
                    headers TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    is_valid INTEGER NOT NULL,
                    PRIMARY KEY (role, target)
                )
                """
            )

    def save(self, session: Session) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO sessions (role, target, session_id, user_id, auth_type, cookies, headers,
                                       created_at, expires_at, is_valid)
                VALUES (:role, :target, :session_id, :user_id, :auth_type, :cookies, :headers,
                        :created_at, :expires_at, :is_valid)
                ON CONFLICT(role, target) DO UPDATE SET
                    session_id=excluded.session_id,
                    user_id=excluded.user_id,
                    auth_type=excluded.auth_type,
                    cookies=excluded.cookies,
                    headers=excluded.headers,
                    created_at=excluded.created_at,
                    expires_at=excluded.expires_at,
                    is_valid=excluded.is_valid
                """,
                {**session.to_row(), "target": self._target},
            )

    def load(self, role: str) -> Session | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE role = ? AND target = ?", (role, self._target)).fetchone()
        return Session.from_row(dict(row)) if row else None

    def load_all(self) -> dict[str, Session]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM sessions WHERE target = ?", (self._target,)).fetchall()
        return {row["role"]: Session.from_row(dict(row)) for row in rows}

    def delete(self, role: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE role = ? AND target = ?", (role, self._target))
