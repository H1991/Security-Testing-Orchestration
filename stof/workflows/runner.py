"""Layer 6 — executes a workflow via the Playwright engine (Layer 3B).

The ONLY module that calls `engine.playwright_engine.replay()` --
vulnerability modules call `WorkflowRunner.run_workflow(workflow_id,
session)` instead, never the engine directly.

Also where `{{user.username}}`/`{{user.password}}` tokens get resolved,
at replay time, from the active Session -- per CLAUDE.md. One real gap
in that spec: `Session` (Layer 5) deliberately carries no credential
material, only session state (cookies/headers/validity/user_id/role).
So "resolved from the active Session" in practice means: look up the
`UserConfig` (Layer 1's source of truth for credentials) that
`session.user_id` identifies, and pull the literal value from there.
"""
from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from stof.core.logger import get_logger
from stof.engine.playwright_engine import PlaywrightEngine, ReplayResult
from stof.session.models import Session

from .models import Workflow
from .repository import WorkflowRepository

if TYPE_CHECKING:
    from stof.config.schema import UsersConfig

_log = get_logger("workflows.runner")

_TOKEN_FIELDS = {
    "{{user.username}}": "username",
    "{{user.password}}": "password",
}


class WorkflowRunner:
    def __init__(
        self,
        repository: WorkflowRepository,
        engine: PlaywrightEngine,
        users: "UsersConfig",
    ) -> None:
        self._repository = repository
        self._engine = engine
        self._users_by_id = {user.id: user for user in users.users}

    async def run_workflow(self, workflow_id: str, session: Session) -> ReplayResult:
        workflow = self._repository.get(workflow_id)
        resolved = self._resolve_tokens(workflow, session)
        return await self._engine.replay(resolved.to_dict(), session)

    def _resolve_tokens(self, workflow: Workflow, session: Session) -> Workflow:
        user = self._users_by_id.get(session.user_id)
        resolved_actions = []

        for action in workflow.actions:
            field_name = _TOKEN_FIELDS.get(action.value)
            if field_name is None:
                resolved_actions.append(action)
                continue

            if user is None:
                _log.warning(
                    f"cannot resolve token '{action.value}': no configured user with "
                    f"id '{session.user_id}' (session role={session.role}); "
                    "leaving token unresolved"
                )
                resolved_actions.append(action)
                continue

            resolved_actions.append(replace(action, value=getattr(user, field_name)))

        return replace(workflow, actions=resolved_actions)
