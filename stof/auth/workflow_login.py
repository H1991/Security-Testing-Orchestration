"""Layer 4 — Recorded-workflow login provider.

The "recorded login sequence" every major DAST tool (Burp, Acunetix,
Invicti) leans on as its primary answer to a login `FormLoginProvider`'s
field-name auto-detection can't handle -- an unusual SPA login form, a
multi-step flow, anything with more shape than "one username field, one
password field, one submit button". Burp's own docs recommend it even
for a plain username/password site, since it doubles as the
still-logged-in check.

STOF already has both halves of this: the RECORDING half
(`stof/recorder/`, CDP-attach to a real operator browser) and the
REPLAY half (`stof/workflows/`, `PlaywrightEngine.replay()`). This
provider is the missing connection between them: pick one of those
already-recorded workflows as a role's login method
(`UserConfig.auth_type == "recorded_workflow"`, `UserConfig.
login_workflow_id` naming which one), the same way `"form_login"`/
`"jwt"` already select a login mechanism per role.

Token resolution here is deliberately simpler than `workflows/
runner.py`'s own `WorkflowRunner._resolve_tokens()`: that method starts
from a `Session` and looks up the `UserConfig` it belongs to (`Session`
carries no credential material, only session state), because its only
caller (`run_workflow(workflow_id, session)`) never has the `UserConfig`
directly. `authenticate()` here is handed the full `UserConfig` already
(the same signature every `AuthProvider` implements), so resolving
`{{user.username}}`/`{{user.password}}` needs no Session-based
indirection -- just a direct attribute lookup.

Runs the workflow's actions directly on the `page` the caller handed in
via `stof.engine.playwright_engine.execute_action` (the SAME action
dispatch `PlaywrightEngine.replay()` itself uses, not a second copy of
the navigate/fill/click/wait_for switch), rather than calling
`PlaywrightEngine.replay()` itself -- that method closes the page when
it's done (it opened it), but an `AuthProvider.authenticate()` never
owns the page it's handed (see `stof/auth/base.py`'s docstring;
`FormLoginProvider`/`AssistedLoginProvider` both leave the page open
for their caller), so this provider follows that same convention.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from stof.core.logger import get_logger
from stof.engine.playwright_engine import execute_action
from stof.session.models import Session
from stof.workflows.repository import WorkflowNotFoundError

from .base import AuthExpiredError, AuthFailedError, AuthProvider
from .form_login import extract_cookies, extract_storage_token, wait_for_login_success

if TYPE_CHECKING:
    from playwright.async_api import Page

    from stof.config.schema import UserConfig
    from stof.workflows.repository import WorkflowRepository

_log = get_logger("auth.workflow_login")

_TOKEN_FIELDS = {"{{user.username}}": "username", "{{user.password}}": "password"}

# Same generous-but-bounded shape `AssistedLoginProvider` uses for its
# own session lifetime -- a recorded workflow (unlike a JWT's own real
# `exp` claim) carries no expiry signal of its own to read, and this
# session refreshes by full re-authenticate() anyway (see `refresh()`
# below), so the exact value mostly just bounds how often that happens.
DEFAULT_SESSION_LIFETIME = timedelta(hours=6)

# A generic "did the recorded flow actually land somewhere real"
# sanity wait, used only when the workflow itself has no explicit
# `wait_for` as its last action -- mirrors `FormLoginProvider`'s own
# generic success detection rather than requiring every recording to
# hand-author one.
_SETTLE_TIMEOUT_MS = 10_000


def _resolve_action_value(value: str | None, user: "UserConfig") -> str | None:
    field_name = _TOKEN_FIELDS.get(value or "")
    return getattr(user, field_name) if field_name else value


class WorkflowLoginProvider(AuthProvider):
    def __init__(self, repository: "WorkflowRepository", session_lifetime: timedelta = DEFAULT_SESSION_LIFETIME) -> None:
        self._repository = repository
        self._session_lifetime = session_lifetime

    @staticmethod
    async def _replay_login_actions(page: "Page", workflow, user: "UserConfig") -> None:
        """Runs every action, resolving `{{user.username}}`/
        `{{user.password}}` tokens as it goes -- pulled out of
        `authenticate()` purely to keep that method's own branching
        under this project's complexity gate (CLAUDE.md's own quality
        standard)."""
        for action in workflow.actions:
            resolved = replace(action, value=_resolve_action_value(action.value, user)) if action.value else action
            try:
                await execute_action(page, resolved.to_dict())
            except Exception as exc:
                raise AuthFailedError(
                    f"recorded workflow '{user.login_workflow_id}' for role '{user.role}' failed on "
                    f"action {resolved.type!r}: {exc}"
                ) from exc

    async def authenticate(self, user: "UserConfig", page: "Page") -> Session:
        if not user.login_workflow_id:
            raise AuthFailedError(f"role '{user.role}' has auth_type 'recorded_workflow' but no login_workflow_id configured")
        try:
            workflow = self._repository.get(user.login_workflow_id)
        except WorkflowNotFoundError as exc:
            raise AuthFailedError(f"role '{user.role}': {exc}") from exc

        ends_with_wait = bool(workflow.actions) and workflow.actions[-1].type == "wait_for"
        await self._replay_login_actions(page, workflow, user)
        if not ends_with_wait:
            # The recording itself didn't assert a specific post-login
            # element -- give the page a moment to finish whatever
            # navigation/rendering the last click triggered before
            # reading cookies/storage, the same generic settle
            # `wait_for_login_success` gives FormLoginProvider's own
            # submit when no success_selector is configured.
            await wait_for_login_success(page, workflow.target_url, None, _SETTLE_TIMEOUT_MS, f"recorded workflow (role={user.role})")

        cookies = await extract_cookies(page)
        storage_token = await extract_storage_token(page)
        headers = {"Authorization": f"Bearer {storage_token}"} if storage_token else {}
        if not cookies and not headers:
            raise AuthFailedError(
                f"recorded workflow '{user.login_workflow_id}' for role '{user.role}' finished with no cookies "
                "and no recognizable SPA token in storage -- the recording may not actually complete a login "
                "(re-record it, watching that the last step reaches a genuinely logged-in page)"
            )
        expires_at = datetime.now(timezone.utc) + self._session_lifetime
        session = Session(user_id=user.id, role=user.role, auth_type="recorded_workflow", cookies=cookies, headers=headers, expires_at=expires_at)
        _log.info(f"authenticated role '{user.role}' via recorded workflow '{user.login_workflow_id}' (session_id={session.session_id})")
        return session

    async def refresh(self, session: Session, page: "Page") -> Session:
        # A recorded workflow is cheap to re-run (no human needed, unlike
        # AssistedLoginProvider's own refresh()) -- re-authenticating from
        # scratch by replaying it again is both correct and simpler than
        # a bespoke incremental-refresh path this login method has no
        # real way to support. `try_refresh()` (stof/session/token_
        # refresh.py) treats this exactly like FormLoginProvider's own
        # always-raises refresh(): "give up, caller re-authenticates."
        raise AuthExpiredError(f"recorded_workflow session {session.session_id} needs a fresh authenticate(), not an in-place refresh")

    async def is_authenticated(self, session: Session, page: "Page") -> bool:
        if not session.is_valid:
            return False
        current_cookies = await extract_cookies(page)
        return all(current_cookies.get(name) == value for name, value in session.cookies.items())
