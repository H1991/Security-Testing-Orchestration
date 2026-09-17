"""Layer 7 — normalise + persist discovered endpoints.

Writes `data/endpoints.json` -- the only thing vulnerability modules
read (via `load()`); they never call the crawler directly, per
CLAUDE.md. Also mirrors to SQLite for cross-scan comparison.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from stof.core.logger import get_logger

_log = get_logger("crawler.endpoint_store")

DEFAULT_ENDPOINTS_PATH = Path("data/endpoints.json")
DEFAULT_DB_PATH = Path("data/stof.db")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Endpoint:
    url: str
    method: str
    endpoint_type: str  # "page" | "form" | "api" | "websocket"
    parameters: list[str] = field(default_factory=list)
    # Where each entry in `parameters` actually lives -- "query" | "body" |
    # "header" | "cookie". Injection modules (SQLi/XSS) need this to place
    # a payload correctly; a name missing from this dict (e.g. every
    # `Endpoint` written by a pre-Wave-1 scan, or a "page" endpoint with no
    # tracked params at all) defaults to "query" via `location_for()` below
    # -- additive-only, so every existing `e.parameters` call site (IDOR,
    # BFLA, ...) is unaffected. Header/cookie discovery isn't implemented
    # yet (the crawler doesn't observe per-endpoint request headers); the
    # value is supported for future use.
    param_locations: dict[str, str] = field(default_factory=dict)
    # A snapshot of each input's `value` attribute at crawl time (name ->
    # value), for entries that had a non-empty one -- a `<form>`'s hidden
    # anti-CSRF token field being the motivating case (`csrf_tests.py`
    # needs the real token value to submit a working baseline request,
    # not just the field's name). Additive-only, same convention
    # `param_locations` itself established: a name missing here (any
    # `Endpoint` written by a pre-Wave-3 scan, or a field with no `value`
    # attribute at all) just means "no captured value", not an error --
    # every existing `e.parameters` call site is unaffected.
    parameter_values: dict[str, str] = field(default_factory=dict)
    auth_required: bool = False
    discovered_at: datetime = field(default_factory=_utcnow)

    def key(self) -> tuple[str, str]:
        """Dedup identity: (method, url)."""
        return (self.method.upper(), self.url)

    def location_for(self, name: str) -> str:
        """Where parameter `name` lives. Defaults to "query" for any
        param not explicitly tagged -- see `param_locations` docstring."""
        return self.param_locations.get(name, "query")

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "endpoint_type": self.endpoint_type,
            "parameters": self.parameters,
            "param_locations": self.param_locations,
            "parameter_values": self.parameter_values,
            "auth_required": self.auth_required,
            "discovered_at": self.discovered_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Endpoint:
        return cls(
            url=data["url"],
            method=data["method"],
            endpoint_type=data["endpoint_type"],
            parameters=data.get("parameters", []),
            param_locations=data.get("param_locations", {}),
            parameter_values=data.get("parameter_values", {}),
            auth_required=data.get("auth_required", False),
            discovered_at=datetime.fromisoformat(data["discovered_at"]),
        )


def dedupe(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Collapse endpoints sharing a (method, url) key, keeping the
    first-seen occurrence but merging their parameter lists (and each
    param's location -- first-seen location wins on a rare conflict,
    same "first occurrence is authoritative" rule already used for the
    rest of the kept endpoint's fields)."""
    merged: dict[tuple[str, str], Endpoint] = {}
    for endpoint in endpoints:
        key = endpoint.key()
        existing = merged.get(key)
        if existing is None:
            merged[key] = endpoint
        else:
            existing.parameters = list(dict.fromkeys(existing.parameters + endpoint.parameters))
            for name, location in endpoint.param_locations.items():
                existing.param_locations.setdefault(name, location)
            for name, value in endpoint.parameter_values.items():
                existing.parameter_values.setdefault(name, value)
    return list(merged.values())


def merge(existing: list[Endpoint], new: list[Endpoint]) -> list[Endpoint]:
    """Union two endpoint lists collected from separate crawls (e.g. two
    different roles) -- a low-priv role's crawl must not lose an
    admin-only endpoint an earlier admin-role crawl already found, or
    vice versa. `dedupe()` already implements exactly this "same
    (method, url), union the params" merge for a single list; feeding it
    the concatenation reuses that one code path instead of duplicating
    the merge logic here. `existing` entries are placed first, so on the
    rare param-location conflict `existing`'s tag wins, matching
    dedupe()'s general first-seen-wins rule."""
    return dedupe(existing + new)


def write_endpoints(endpoints: list[Endpoint], path: str | Path = DEFAULT_ENDPOINTS_PATH) -> Path:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps([e.to_dict() for e in endpoints], indent=2) + "\n", encoding="utf-8"
    )
    _log.info(f"wrote {len(endpoints)} endpoint(s) -> {output_path}")
    return output_path


def load(path: str | Path = DEFAULT_ENDPOINTS_PATH) -> list[Endpoint]:
    """Load `endpoints.json`. Returns `[]` if it doesn't exist yet
    (e.g. crawler disabled via `modules.crawler: false`)."""
    input_path = Path(path)
    if not input_path.is_file():
        return []
    raw = json.loads(input_path.read_text(encoding="utf-8"))
    return [Endpoint.from_dict(item) for item in raw]


class EndpointDB:
    """SQLite mirror for cross-scan comparison (same `data/stof.db` used
    by Layer 2's job checkpoints and Layer 5's session store)."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        # WAL + NORMAL sync -- same reasoning as the other data/stof.db
        # stores (findings, sessions, orchestrator checkpoints): readers
        # no longer block behind a writer on this shared file, and each
        # commit skips the extra fsync default mode pays.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS endpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    method TEXT NOT NULL,
                    endpoint_type TEXT NOT NULL,
                    parameters TEXT NOT NULL,
                    auth_required INTEGER NOT NULL,
                    discovered_at TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_endpoints_scan_id ON endpoints(scan_id)")

    def save(self, scan_id: str, endpoints: list[Endpoint]) -> None:
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO endpoints (scan_id, url, method, endpoint_type, parameters,
                                        auth_required, discovered_at)
                VALUES (:scan_id, :url, :method, :endpoint_type, :parameters,
                        :auth_required, :discovered_at)
                """,
                [
                    {
                        "scan_id": scan_id,
                        "url": e.url,
                        "method": e.method,
                        "endpoint_type": e.endpoint_type,
                        "parameters": json.dumps(e.parameters),
                        "auth_required": int(e.auth_required),
                        "discovered_at": e.discovered_at.isoformat(),
                    }
                    for e in endpoints
                ],
            )

    def load_scan(self, scan_id: str) -> list[Endpoint]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM endpoints WHERE scan_id = ?", (scan_id,)).fetchall()
        return [
            Endpoint(
                url=row["url"],
                method=row["method"],
                endpoint_type=row["endpoint_type"],
                parameters=json.loads(row["parameters"]),
                auth_required=bool(row["auth_required"]),
                discovered_at=datetime.fromisoformat(row["discovered_at"]),
            )
            for row in rows
        ]

    def list_scan_ids(self) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT DISTINCT scan_id FROM endpoints ORDER BY scan_id").fetchall()
        return [row["scan_id"] for row in rows]
