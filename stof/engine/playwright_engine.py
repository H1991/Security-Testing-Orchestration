"""Layer 3B — async workflow replay.

`workflow` is accepted as the plain neutral-JSON dict documented in
CLAUDE.md (`workflow_id`/`target_url`/`recorded_at`/`actions`) rather
than a `workflows.models.Workflow` instance, and `session` is typed as
the structural `SessionLike` protocol (see `multi_session.py`) rather
than importing Layer 5's concrete `Session` dataclass -- neither Layer 6
nor Layer 5 exist yet in this incremental build. Layer 3A already
produces exactly this workflow shape, and a real `Session`/`Workflow`
instance will satisfy these contracts structurally once those layers
land, with no change needed here.

Credential token resolution (`{{user.username}}` etc.) is Layer 6's
(`workflows/runner.py`) responsibility per CLAUDE.md, not this module's
-- `replay()` executes action values literally.

`ReplayResult.success` means "every action executed without a Playwright
error" -- NOT "the workflow achieved its intended app-level outcome"
(e.g. a login form that silently re-renders on bad credentials, rather
than erroring, "succeeds" by this definition even though login failed).
`final_status_code`/`response_log` (the HTTP status of each top-level
page load) are one signal for that judgement, but many apps -- this
project's own demo.testfire.net included -- return 200 for both a
successful and a rejected login. The reliable way to assert an
app-level outcome is a `wait_for` action targeting an element/text that
only appears on success (or absence of one that only appears on
failure); that is a workflow-authoring concern, not something this
generic engine can infer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from stof.core.logger import get_logger

from .multi_session import SessionLike, SessionPool

if TYPE_CHECKING:
    from playwright.async_api import Page, Response

_log = get_logger("engine.playwright_engine")


class UnknownActionType(Exception):
    """Raised internally for an action type not in the documented
    navigate/fill/click/wait_for schema; surfaced via `ReplayResult`,
    never allowed to propagate out of `replay()`."""


@dataclass
class ReplayResult:
    workflow_id: str
    success: bool
    completed_actions: int
    total_actions: int
    final_url: str
    error: str | None = None
    final_status_code: int | None = None
    response_log: list[dict[str, Any]] = field(default_factory=list)


class PlaywrightEngine:
    def __init__(self, session_pool: SessionPool) -> None:
        self._pool = session_pool

    async def replay(self, workflow: dict[str, Any], session: SessionLike) -> ReplayResult:
        actions: list[dict[str, Any]] = workflow.get("actions", [])
        target_url = workflow.get("target_url", "")
        workflow_id = workflow.get("workflow_id", "")

        context = await self._pool.apply_session(session, target_url)
        page = await context.new_page()

        response_log: list[dict[str, Any]] = []

        def _on_response(response: "Response") -> None:
            # Only top-level page loads, not every image/script/xhr --
            # this is what "navigate" and a form-submit click produce.
            if response.request.resource_type == "document":
                response_log.append({"url": response.url, "status": response.status})

        page.on("response", _on_response)

        completed = 0
        error: str | None = None

        try:
            for action in actions:
                await execute_action(page, action)
                completed += 1
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            _log.error(f"workflow {workflow_id}: action {completed} failed: {exc}")

        final_url = page.url
        final_status_code = response_log[-1]["status"] if response_log else None
        page.remove_listener("response", _on_response)
        await page.close()

        return ReplayResult(
            workflow_id=workflow_id,
            success=error is None,
            completed_actions=completed,
            total_actions=len(actions),
            final_url=final_url,
            error=error,
            final_status_code=final_status_code,
            response_log=response_log,
        )


async def execute_action(page: "Page", action: dict[str, Any]) -> None:
    """The navigate/fill/click/wait_for dispatch every workflow replay
    ultimately runs -- a free function (not a `PlaywrightEngine` method)
    so `stof/auth/workflow_login.py`'s `WorkflowLoginProvider` can reuse
    the exact same action execution for a recorded LOGIN workflow
    without duplicating it. `PlaywrightEngine.replay()` above closes the
    page itself when it's done (it created that page), which is why
    `WorkflowLoginProvider` doesn't call `replay()` directly -- an
    `AuthProvider.authenticate()` never owns the page it's handed (see
    `stof/auth/base.py`'s docstring; `FormLoginProvider`/
    `AssistedLoginProvider` both leave the page open for their caller),
    so it needs this lower-level piece instead."""
    action_type = action.get("type")
    if action_type == "navigate":
        await page.goto(action["url"])
    elif action_type == "fill":
        await page.fill(action["selector"], action.get("value", ""))
    elif action_type == "click":
        await page.click(action["selector"])
    elif action_type == "wait_for":
        await page.wait_for_selector(action["selector"], timeout=action.get("timeout_ms", 5000))
    else:
        raise UnknownActionType(f"unknown action type: {action_type!r}")
