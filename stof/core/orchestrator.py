"""Layer 2 — Orchestrator / scan engine.

Fans out work to later layers, manages Job lifecycle, checkpoints state
to SQLite after each layer, and handles retries.

Layer-wiring note: CLAUDE.md describes orchestrator.py as the one module
that imports every layer (engine, recorder, crawler, auth, session,
workflows, modules, findings, evidence, reporting) to tie them together.
Those packages don't exist yet in this incremental, layer-by-layer build,
so `Orchestrator.run()` takes an ordered list of `ScanPhase` objects
instead of importing them directly. Each `ScanPhase` wraps one later
layer's entry point as an injected async callable. As each layer is
built, its phase gets added to the list passed in by the caller (Layer
2's own job-lifecycle/checkpoint/retry machinery below does not change).
This keeps this module importable and testable today without a hard
dependency on packages that haven't been written yet.
"""
from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from stof.config import Config

from .job import Job, JobStatus
from .logger import get_logger

DEFAULT_DB_PATH = Path("data/stof.db")

PhaseFn = Callable[[Job], Awaitable[None]]


@dataclass
class ScanPhase:
    """One fan-out step of a scan (e.g. Layer 4 auth, Layer 7 crawl,
    Layer 9 modules, Layer 13 reporting)."""

    name: str
    run: PhaseFn


class Orchestrator:
    """Job scheduling, lifecycle management, SQLite checkpointing, retry.

    State is checkpointed before/after every phase, so a crash mid-scan
    can resume from the last in-progress layer instead of layer 1.
    """

    def __init__(
        self,
        config: Config,
        db_path: str | Path = DEFAULT_DB_PATH,
        max_retries: int = 2,
        retry_backoff_seconds: float = 0.0,
    ) -> None:
        self.config = config
        self.db_path = Path(db_path)
        self.max_retries = max_retries
        self.retry_backoff_seconds = retry_backoff_seconds
        self._log = get_logger("core.orchestrator")
        self._init_db()

    # -- SQLite checkpoint store -----------------------------------------

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        # WAL + NORMAL sync: same reasoning as session_store.py/
        # findings/store.py's identical pragmas -- shares this same
        # data/stof.db file, so job-checkpoint writes here don't lock
        # out readers/writers from the other two stores.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    enabled_modules TEXT NOT NULL,
                    status TEXT NOT NULL,
                    current_layer TEXT,
                    retry_count INTEGER NOT NULL,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

    def _save(self, job: Job) -> None:
        row = job.to_row()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO jobs (job_id, target_url, enabled_modules, status,
                                   current_layer, retry_count, error, created_at, updated_at)
                VALUES (:job_id, :target_url, :enabled_modules, :status,
                        :current_layer, :retry_count, :error, :created_at, :updated_at)
                ON CONFLICT(job_id) DO UPDATE SET
                    status=excluded.status,
                    current_layer=excluded.current_layer,
                    retry_count=excluded.retry_count,
                    error=excluded.error,
                    updated_at=excluded.updated_at
                """,
                row,
            )

    def load_job(self, job_id: str) -> Job | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        return Job.from_row(dict(row)) if row else None

    # -- job lifecycle -----------------------------------------------------

    def create_job(self, target_url: str, enabled_modules: list[str]) -> Job:
        job = Job(target_url=target_url, enabled_modules=enabled_modules)
        self._save(job)
        self._log.info(f"Job {job.job_id} created (QUEUED) target={target_url}")
        return job

    async def run(self, job: Job, phases: list[ScanPhase]) -> Job:
        """Advance `job` through `phases` in order, checkpointing before
        each phase and retrying a failed phase up to `max_retries` times
        before failing the job. If `job.current_layer` is already set
        (resumed after a crash), execution restarts at that phase rather
        than from the beginning.
        """
        if job.status in (JobStatus.QUEUED, JobStatus.PAUSED, JobStatus.RETRY):
            job.transition(JobStatus.RUNNING)
            self._save(job)

        start_index = 0
        if job.current_layer is not None:
            names = [phase.name for phase in phases]
            if job.current_layer in names:
                start_index = names.index(job.current_layer)

        for phase in phases[start_index:]:
            job.current_layer = phase.name
            self._save(job)
            self._log.info(f"Job {job.job_id}: running phase '{phase.name}'")

            attempt = 0
            while True:
                try:
                    await phase.run(job)
                    break
                except Exception as exc:
                    attempt += 1
                    job.error = f"{phase.name}: {exc}"
                    if attempt > self.max_retries:
                        job.transition(JobStatus.FAILED)
                        self._save(job)
                        self._log.error(
                            f"Job {job.job_id}: phase '{phase.name}' failed "
                            f"permanently after {attempt - 1} retries: {exc}"
                        )
                        return job

                    job.retry_count += 1
                    job.transition(JobStatus.FAILED)
                    job.transition(JobStatus.RETRY)
                    job.transition(JobStatus.RUNNING)
                    self._save(job)
                    self._log.warning(
                        f"Job {job.job_id}: phase '{phase.name}' failed "
                        f"(attempt {attempt}/{self.max_retries}), retrying: {exc}"
                    )
                    if self.retry_backoff_seconds:
                        await asyncio.sleep(self.retry_backoff_seconds * attempt)

        job.current_layer = None
        job.error = None
        job.transition(JobStatus.COMPLETED)
        self._save(job)
        self._log.info(f"Job {job.job_id}: COMPLETED")
        return job
