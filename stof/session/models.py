"""Layer 5 — Session Manager: the `Session` data contract.

(Created ahead of the rest of Layer 5, during Layer 4: CLAUDE.md's own
`auth/base.py` spec does `from stof.session.models import Session`, so
this had to exist before Layer 4 could be written.)
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Session:
    user_id: str
    role: str
    auth_type: str
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=_utcnow)
    expires_at: datetime | None = None
    is_valid: bool = True

    def to_row(self) -> dict[str, Any]:
        """Serialise to a flat dict of SQLite-storable primitives."""
        return {
            "role": self.role,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "auth_type": self.auth_type,
            "cookies": json.dumps(self.cookies),
            "headers": json.dumps(self.headers),
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_valid": int(self.is_valid),
        }

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> Session:
        return cls(
            role=row["role"],
            session_id=row["session_id"],
            user_id=row["user_id"],
            auth_type=row["auth_type"],
            cookies=json.loads(row["cookies"]),
            headers=json.loads(row["headers"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            is_valid=bool(row["is_valid"]),
        )
