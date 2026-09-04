"""Layer 10 — normalise + persist findings.

Mirrors `crawler/endpoint_store.py`'s shape exactly (`write_*`/`load`
JSON pair + a SQLite mirror class) -- same persistence pattern, same
`data/stof.db`, one row per scan via `scan_id`.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from stof.core.logger import get_logger

from .models import Finding

_log = get_logger("findings.store")

DEFAULT_FINDINGS_PATH = Path("data/findings.json")
DEFAULT_DB_PATH = Path("data/stof.db")


def write_findings(findings: list[Finding], path: str | Path = DEFAULT_FINDINGS_PATH) -> Path:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps([f.to_dict() for f in findings], indent=2) + "\n", encoding="utf-8"
    )
    _log.info(f"wrote {len(findings)} finding(s) -> {output_path}")
    return output_path


def load(path: str | Path = DEFAULT_FINDINGS_PATH) -> list[Finding]:
    """Load `findings.json`. Returns `[]` if it doesn't exist yet
    (e.g. no scan has run, or every vulnerability module was disabled)."""
    input_path = Path(path)
    if not input_path.is_file():
        return []
    raw = json.loads(input_path.read_text(encoding="utf-8"))
    return [Finding.from_dict(item) for item in raw]


class FindingDB:
    """SQLite mirror for cross-scan comparison, same convention as
    `EndpointDB`."""

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
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    module_id TEXT NOT NULL,
                    vuln_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    cvss_score REAL NOT NULL,
                    endpoint TEXT NOT NULL,
                    user_role TEXT NOT NULL,
                    request_raw TEXT NOT NULL,
                    response_raw TEXT NOT NULL,
                    evidence_refs TEXT NOT NULL,
                    description TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    discovered_at TEXT NOT NULL,
                    scanner_source TEXT NOT NULL,
                    technique_id TEXT,
                    cwe TEXT,
                    owasp_category TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
            # Additive migration for a `findings` table created before
            # these three columns existed -- `CREATE TABLE IF NOT EXISTS`
            # above is a no-op against an already-created table, so an
            # older on-disk data/stof.db needs them added explicitly.
            # Never actually hit in production yet (this table has no
            # writer wired into main.py/server.py as of this change),
            # but a stale local test DB from earlier development could
            # still have the old shape.
            existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
            for column in ("technique_id", "cwe", "owasp_category"):
                if column not in existing_cols:
                    conn.execute(f"ALTER TABLE findings ADD COLUMN {column} TEXT")

    def save(self, scan_id: str, findings: list[Finding]) -> None:
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO findings (scan_id, finding_id, module_id, vuln_type, severity,
                                       cvss_score, endpoint, user_role, request_raw, response_raw,
                                       evidence_refs, description, recommendation, discovered_at,
                                       scanner_source, technique_id, cwe, owasp_category)
                VALUES (:scan_id, :finding_id, :module_id, :vuln_type, :severity,
                         :cvss_score, :endpoint, :user_role, :request_raw, :response_raw,
                         :evidence_refs, :description, :recommendation, :discovered_at,
                         :scanner_source, :technique_id, :cwe, :owasp_category)
                """,
                [{"scan_id": scan_id, **f.to_row()} for f in findings],
            )

    def load_scan(self, scan_id: str) -> list[Finding]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
        return [Finding.from_row(dict(row)) for row in rows]

    def list_scan_ids(self) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT DISTINCT scan_id FROM findings ORDER BY scan_id").fetchall()
        return [row["scan_id"] for row in rows]
