"""Layer 6 — NeutralAction, Workflow data contracts.

`to_dict()` produces exactly the neutral JSON shape Layer 3A's exporter
has been writing (and Layer 3B's `playwright_engine.replay()` has been
accepting as a plain dict) since before this layer existed -- see those
modules' docstrings. That's deliberate: nothing in Layers 3A/3B needs to
change now that this formal contract exists.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class NeutralAction:
    type: str
    selector: str | None = None
    url: str | None = None
    value: str | None = None
    timeout_ms: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Only emit fields that are actually set, matching the compact
        shape Layer 3A's exporter writes (a `navigate` action has no
        `selector` key at all, not `selector: null`)."""
        data: dict[str, Any] = {"type": self.type}
        if self.selector is not None:
            data["selector"] = self.selector
        if self.url is not None:
            data["url"] = self.url
        if self.value is not None:
            data["value"] = self.value
        if self.timeout_ms is not None:
            data["timeout_ms"] = self.timeout_ms
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NeutralAction:
        return cls(
            type=data["type"],
            selector=data.get("selector"),
            url=data.get("url"),
            value=data.get("value"),
            timeout_ms=data.get("timeout_ms"),
        )


@dataclass
class Workflow:
    workflow_id: str
    target_url: str
    actions: list[NeutralAction] = field(default_factory=list)
    recorded_at: datetime | None = None
    # Human-readable name (per CLAUDE.md's Layer 6 spec). Not part of the
    # neutral JSON schema itself -- repository.py derives it from the
    # filename, since Layer 3A's exporter never writes a name field.
    name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "target_url": self.target_url,
            "recorded_at": self.recorded_at.isoformat() if self.recorded_at else None,
            "actions": [action.to_dict() for action in self.actions],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], name: str | None = None) -> Workflow:
        recorded_at_raw = data.get("recorded_at")
        return cls(
            workflow_id=data["workflow_id"],
            target_url=data["target_url"],
            actions=[NeutralAction.from_dict(action) for action in data.get("actions", [])],
            recorded_at=datetime.fromisoformat(recorded_at_raw) if recorded_at_raw else None,
            name=name,
        )
