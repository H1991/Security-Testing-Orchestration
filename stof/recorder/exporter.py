"""Layer 3A — exports captured events as neutral JSON workflow actions.

Owns the on-disk `Workflow` JSON contract documented in CLAUDE.md and the
credential-tokenisation rule: recorded `fill` values are replaced with
`{{user.username}}` / `{{user.password}}` tokens (resolved later, at
replay time, from `users.json`) so literal credentials never land in a
committed workflow file.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from stof.config import UsersConfig
from stof.core.logger import get_logger

_log = get_logger("recorder.exporter")

REDACTED_PLACEHOLDER = "{{REDACTED}}"


def new_workflow_id() -> str:
    return f"wf-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:6]}"


def _match_credential_token(value: str, users: UsersConfig | None) -> str | None:
    if not value or users is None:
        return None
    for user in users.users:
        if value == user.password:
            return "{{user.password}}"
        if value == user.username:
            return "{{user.username}}"
    return None


def tokenize_credentials(
    actions: list[dict[str, Any]], users: UsersConfig | None = None
) -> list[dict[str, Any]]:
    """Return a copy of `actions` with recorded credential values replaced
    by `{{user.username}}` / `{{user.password}}` tokens.

    A `fill` action whose value matches a configured user's username or
    password is tokenised. A `fill` action on a `password`-type field
    that matches no configured user is redacted (never written verbatim)
    and a warning is logged so the tester can fix it by hand.

    The internal `field_type` key (set by `event_handler.py` to identify
    password fields) is stripped before the action is returned, since
    it is not part of the documented neutral action schema.
    """
    tokenized: list[dict[str, Any]] = []
    for action in actions:
        action = dict(action)
        field_type = action.pop("field_type", None)

        if action.get("type") == "fill":
            value = action.get("value", "")
            token = _match_credential_token(value, users)
            if token is not None:
                action["value"] = token
            elif field_type == "password":
                _log.warning(
                    f"recorded password field '{action.get('selector')}' did not match "
                    "any configured user; redacting instead of storing it in plain "
                    "text. Edit the workflow file to use a {{user.password}} token."
                )
                action["value"] = REDACTED_PLACEHOLDER

        tokenized.append(action)
    return tokenized


def build_workflow(
    target_url: str,
    actions: list[dict[str, Any]],
    workflow_id: str | None = None,
) -> dict[str, Any]:
    """Build the neutral JSON workflow document (see CLAUDE.md Layer 3A)."""
    return {
        "workflow_id": workflow_id or new_workflow_id(),
        "target_url": target_url,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "actions": actions,
    }


def write_workflow(workflow: dict[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(workflow, indent=2) + "\n", encoding="utf-8")
    return path
