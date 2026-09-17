"""Cleanup/teardown ledger for state-changing techniques.

Real, previously-unaddressed gap this closes: every technique gated
behind `allow_state_changing_probes` (stored-XSS/SQLi/CSV plants,
account creation, password changes, file uploads) performs a REAL write
against the target, but nothing anywhere tracked what got created or
attempted to remove it afterward. The safety posture this project has
always documented ("gated, off by default, candidate-detect only") was
only true about STARTING a write -- a scan that plants a marker into a
production comment field or creates a test account and never records
either is still leaving real state behind, which is itself a finding
if it happened against a target STOF doesn't own.

**Tracking first, revert second, and honest about the difference.**
Most planted content (a stored-XSS marker in a comment field, a
second-order SQLi payload) has NO generic, safe delete mechanism this
tool can discover on an arbitrary target -- inventing one risks doing
MORE damage than the plant itself (guessing at a delete endpoint on a
real target is its own safety problem). So this registry's primary job
is honest visibility: record every real write the moment it happens
(persisted immediately, not batched at scan end, so a crash mid-scan
still leaves an accurate ledger an operator can read), and report
"planted, not cleaned (no generic revert mechanism)" as a distinct,
visible status rather than letting it vanish. Where a technique DOES
have a real, safe, already-implemented revert (auth_tests.py's
password-change probes already revert synchronously in their own
`finally` block), this registry just makes that outcome visible in the
report too -- it doesn't reimplement or second-guess it.

**Process-wide singleton, matching `stof/core/rate_limiter.py`'s exact
convention and its own stated reasoning**: every module sharing one
scan subprocess needs to write into the SAME ledger, not one scoped to
a single `VulnModule` instance, and since each `stof scan` run is its
own fresh subprocess, there's no concurrent scan sharing this module's
global state to race against.

**SQLite persistence, matching `session_store.py`/`findings/store.py`'s
exact convention**: same `data/stof.db` file, same fresh-connection-per-
call shape, same `CREATE TABLE IF NOT EXISTS` migration-free schema --
deliberately not a new pattern.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from stof.core.logger import get_logger

_log = get_logger("cleanup.registry")

DEFAULT_DB_PATH = Path("data/stof.db")

# cleanup_status values -- the "distinct, visible status" the registry's
# own docstring promises, not folded into a generic PASS/FAIL. A report
# reader should be able to tell "nothing needed cleaning" (there was no
# planted-state row at all) from "something was planted and it's still
# there" (NOT_ATTEMPTED) from "something was planted and STOF actually
# removed it" (REVERTED) from "something was planted, STOF tried to
# remove it, and failed" (REVERT_FAILED) at a glance.
NOT_ATTEMPTED = "not_attempted"
REVERTED = "reverted"
REVERT_FAILED = "revert_failed"

_STATUSES = (NOT_ATTEMPTED, REVERTED, REVERT_FAILED)

_DEFAULT_DETAIL = "no generic revert mechanism exists for this write type -- flagged for manual review/cleanup"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CleanupRegistry:
    """SQLite-backed ledger of every real write a state-changing
    technique performed. One row per planted/created item."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        # WAL + NORMAL sync -- same reasoning as the other data/stof.db
        # stores (findings, sessions, orchestrator checkpoints, endpoint
        # store): readers no longer block behind a writer on this
        # shared file, and each commit skips the extra fsync default
        # mode pays.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS planted_state (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    module_id TEXT NOT NULL,
                    technique_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    identifier TEXT NOT NULL,
                    endpoint_url TEXT,
                    role TEXT,
                    metadata TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    cleanup_status TEXT NOT NULL,
                    cleanup_detail TEXT NOT NULL
                )
                """
            )

    def record(
        self,
        scan_id: str,
        module_id: str,
        technique_id: str,
        kind: str,
        identifier: str,
        endpoint_url: "str | None" = None,
        role: "str | None" = None,
        metadata: "dict[str, Any] | None" = None,
        cleanup_status: str = NOT_ATTEMPTED,
        cleanup_detail: str = _DEFAULT_DETAIL,
    ) -> str:
        """Records one planted/created item. Called at write-time, right
        after the real write succeeded -- not reconstructed after the
        fact -- so `identifier` should be whatever unique marker/username
        the technique already generated for its own detection oracle
        (every state-changing technique in this codebase already builds
        one, e.g. `f"stof-buslogic-{secrets.token_hex(4)}"`). Returns the
        row's id, for a later `mark_cleanup_result()` call once/if a
        revert is actually attempted."""
        entry_id = str(uuid.uuid4())
        if cleanup_status not in _STATUSES:
            raise ValueError(f"unknown cleanup_status: {cleanup_status!r}, expected one of {_STATUSES!r}")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO planted_state
                    (id, scan_id, module_id, technique_id, kind, identifier, endpoint_url, role,
                     metadata, created_at, cleanup_status, cleanup_detail)
                VALUES (:id, :scan_id, :module_id, :technique_id, :kind, :identifier, :endpoint_url, :role,
                        :metadata, :created_at, :cleanup_status, :cleanup_detail)
                """,
                {
                    "id": entry_id, "scan_id": scan_id, "module_id": module_id, "technique_id": technique_id,
                    "kind": kind, "identifier": identifier, "endpoint_url": endpoint_url, "role": role,
                    "metadata": json.dumps(metadata or {}), "created_at": _utcnow_iso(),
                    "cleanup_status": cleanup_status, "cleanup_detail": cleanup_detail,
                },
            )
        return entry_id

    def mark_cleanup_result(self, entry_id: str, status: str, detail: str) -> None:
        if status not in _STATUSES:
            raise ValueError(f"unknown cleanup_status: {status!r}, expected one of {_STATUSES!r}")
        with self._connect() as conn:
            conn.execute(
                "UPDATE planted_state SET cleanup_status = ?, cleanup_detail = ? WHERE id = ?",
                (status, detail, entry_id),
            )

    def for_scan(self, scan_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM planted_state WHERE scan_id = ? ORDER BY created_at", (scan_id,)
            ).fetchall()
        out = []
        for row in rows:
            entry = dict(row)
            entry["metadata"] = json.loads(entry["metadata"])
            out.append(entry)
        return out


# ---------------------------------------------------------------------------
# Process-wide singleton -- see module docstring for why this, not
# per-VulnModule-instance state, matching `rate_limiter.py`'s convention
# exactly. `configure()` is called once, early, by the scan entrypoint
# (`main.py`), before any module runs.
# ---------------------------------------------------------------------------

_registry: "CleanupRegistry | None" = None
_scan_id: "str | None" = None


def configure(scan_id: str, db_path: "str | Path" = DEFAULT_DB_PATH) -> None:
    global _registry, _scan_id
    _registry = CleanupRegistry(db_path)
    _scan_id = scan_id


def record_planted_state(
    module_id: str,
    technique_id: str,
    kind: str,
    identifier: str,
    endpoint_url: "str | None" = None,
    role: "str | None" = None,
    metadata: "dict[str, Any] | None" = None,
    cleanup_status: str = NOT_ATTEMPTED,
    cleanup_detail: str = _DEFAULT_DETAIL,
) -> "str | None":
    """The call every state-changing technique makes right after its
    real write succeeds. Returns `None` (a no-op) when `configure()`
    hasn't been called -- e.g. a unit test constructing a module
    directly without going through `main.py`'s scan entrypoint -- so
    every existing/new technique call site works unchanged in tests
    with no `CleanupRegistry` wired in. Never raises: a bug in cleanup
    TRACKING must never abort the technique that already performed its
    real write and needs to report its own finding regardless."""
    if _registry is None or _scan_id is None:
        _log.debug("cleanup registry not configured (no active scan_id) -- skipping planted-state tracking")
        return None
    try:
        return _registry.record(
            _scan_id, module_id, technique_id, kind, identifier, endpoint_url, role, metadata,
            cleanup_status, cleanup_detail,
        )
    except Exception as exc:
        _log.warning(f"failed to record planted state for {module_id}/{technique_id}: {exc}")
        return None


def mark_cleanup_result(entry_id: "str | None", status: str, detail: str) -> None:
    """Companion to `record_planted_state` for a technique that DOES
    have a real, already-implemented revert path (e.g. auth_tests.py's
    password-change probes reverting in their own `finally` block) --
    call this with the outcome so it's visible in the report, rather
    than reimplementing or second-guessing that revert logic here.
    A silent no-op if `entry_id` is `None` (the record call above
    itself no-op'd, e.g. registry not configured)."""
    if _registry is None or entry_id is None:
        return
    try:
        _registry.mark_cleanup_result(entry_id, status, detail)
    except Exception as exc:
        _log.warning(f"failed to update cleanup result for entry {entry_id}: {exc}")


def summary_for_current_scan() -> list[dict[str, Any]]:
    """Every planted-state row for the currently `configure()`d scan --
    the exact list `main.py` threads into `scan_metadata["cleanup"]`,
    following the identical 3-hop wiring `skipped_techniques()` already
    established (pure accessor -> scan_metadata key -> report writers)."""
    if _registry is None or _scan_id is None:
        return []
    return _registry.for_scan(_scan_id)
