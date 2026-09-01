"""Job dataclass and lifecycle state machine (Layer 2).

Lifecycle (per CLAUDE.md):
    QUEUED -> RUNNING -> [PAUSED] -> COMPLETED
                       \\-> FAILED -> RETRY -> RUNNING
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class JobStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    RETRY = "RETRY"


ALLOWED_TRANSITIONS: dict[JobStatus, frozenset[JobStatus]] = {
    JobStatus.QUEUED: frozenset({JobStatus.RUNNING}),
    JobStatus.RUNNING: frozenset({JobStatus.PAUSED, JobStatus.COMPLETED, JobStatus.FAILED}),
    JobStatus.PAUSED: frozenset({JobStatus.RUNNING}),
    JobStatus.FAILED: frozenset({JobStatus.RETRY}),
    JobStatus.RETRY: frozenset({JobStatus.RUNNING}),
    JobStatus.COMPLETED: frozenset(),
}


class InvalidJobTransition(Exception):
    """Raised when a Job's status is moved along a transition the
    lifecycle state machine does not allow."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Job:
    target_url: str
    enabled_modules: list[str]
    job_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: JobStatus = JobStatus.QUEUED
    current_layer: str | None = None
    retry_count: int = 0
    error: str | None = None
    created_at: datetime = field(default_factory=_utcnow)
    updated_at: datetime = field(default_factory=_utcnow)

    def transition(self, new_status: JobStatus) -> None:
        allowed = ALLOWED_TRANSITIONS[self.status]
        if new_status not in allowed:
            raise InvalidJobTransition(
                f"job {self.job_id}: cannot move from {self.status.value} "
                f"to {new_status.value}"
            )
        self.status = new_status
        self.updated_at = _utcnow()

    def to_row(self) -> dict[str, Any]:
        """Serialise to a flat dict of SQLite-storable primitives."""
        return {
            "job_id": self.job_id,
            "target_url": self.target_url,
            "enabled_modules": json.dumps(self.enabled_modules),
            "status": self.status.value,
            "current_layer": self.current_layer,
            "retry_count": self.retry_count,
            "error": self.error,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> Job:
        return cls(
            target_url=row["target_url"],
            enabled_modules=json.loads(row["enabled_modules"]),
            job_id=row["job_id"],
            status=JobStatus(row["status"]),
            current_layer=row["current_layer"],
            retry_count=row["retry_count"],
            error=row["error"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
