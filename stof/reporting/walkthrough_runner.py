"""Layer 13 — drives a real Playwright `Page` through each confirmed
FAIL `Finding`'s reproduction, producing a `list[FindingWalkthrough]`.

Lives in `reporting/`, not `modules/`, so per CLAUDE.md's no-cross-
sibling-import rule it cannot import `stof.modules.base`'s
`VulnModule._authenticated_context` -- `_local_authenticated_context()`
below is this file's own small re-implementation of the exact same
primitive calls that helper wraps (`session_pool.get_context()` ->
`context.new_page()` -> `session_manager.get_session()` ->
`session_pool.apply_session()`), built directly against
`stof.engine.multi_session.SessionPool`/`stof.session.session_manager.
SessionManager` -- the same two objects `_authenticated_context` itself
is built on, per Layer 5/3B's own documented contracts. No retry logic
here (unlike the module version): a walkthrough replay is a best-effort
report-quality enhancement, not a security verdict, so a single
transient auth hiccup is treated like any other build_error rather than
retried.

Root-cause fix (see "Rebuild the walkthrough report" plan): the
walkthrough phase used to reuse the SAME cached, shared per-role
`BrowserContext` the live scan itself had already exercised -- by the
time the walkthrough phase runs (last), that context may have been
through real logouts, repeated failed logins, and dozens of other
probes, so its cookie/session state is no longer guaranteed to reflect
a clean, working login. `_fresh_login_context()` performs a REAL login
(the same fill/fill/click/wait-for-navigation mechanics `stof.auth.
form_login.FormLoginProvider.authenticate()` uses, reimplemented here
rather than cross-imported for the same reason `_local_authenticated_
context` is) on a brand-new, isolated `BrowserContext` created via
`session_pool.new_anonymous_context()` -- never touched by the scan's
own techniques. One fresh context is logged in per role and cached for
the duration of the walkthrough build only (not per finding).
"""
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
from typing import TYPE_CHECKING, Callable

from stof.auth.form_login import (
    GENERIC_PASSWORD_SELECTORS,
    GENERIC_SUBMIT_SELECTORS,
    GENERIC_USERNAME_SELECTORS,
)
from stof.core.logger import get_logger
from stof.engine import screenshot as screenshot_module

from .walkthrough_classify import classify_finding, display_tc_id
from .walkthrough_models import FindingWalkthrough, WalkthroughStep
from .walkthrough_players import PLAYERS

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.async_api import BrowserContext

    from stof.config.schema import UserConfig
    from stof.engine.multi_session import SessionPool
    from stof.findings.models import Finding
    from stof.session.session_manager import SessionManager

_log = get_logger("reporting.walkthrough_runner")

# Hard wall-clock budget per finding replay -- reuses the exact
# external-deadline rationale/pattern as `xss_tests.py`'s
# `_navigate_and_check_dialog` (a hung `goto()`/`evaluate()` must never
# be able to stall report generation).
_PLAYER_TIMEOUT_S = 20.0
_LOGIN_TIMEOUT_MS = 15000

ProgressCallback = Callable[[int, int, str], None]


# Not a real configured user -- many techniques (auth_tests.py's
# pre-login/anonymous probes, sqli_tests.py's login-bypass baseline)
# stamp `Finding.user_role = "unauthenticated"` deliberately, since the
# whole point of the finding is that no session was involved. Routing
# that through `session_manager.get_session()` raises `KeyError` (no
# such configured user) -- an anonymous context is the correct replay
# vehicle instead, not an error.
_UNAUTHENTICATED_ROLE = "unauthenticated"

# Players that legitimately benefit from a prepended "Step 1: log in as
# user X" screenshot -- everything that needs an already-authenticated
# starting point. Deliberately excludes players whose OWN first step
# already IS the login page for a different reason (`login_form_
# injection` attacks the login form itself with a bad payload;
# `no_rate_limit` submits the login form repeatedly with wrong
# passwords; `session_after_logout` walks through its own login/logout
# cycle) -- prepending a generic real-login step ahead of those would
# be actively confusing, not helpful.
_PREPEND_LOGIN_STEP_PLAYERS = {
    "url_reflection", "dom_execution", "stored_plant_and_view",
    "csrf_no_token", "authenticated_navigation", "annotated_evidence",
}

# Players that deliberately mutate real session state (a genuine
# logout) must never run against the shared per-role cache -- see
# `_RoleContextCache.get_isolated()`'s own docstring for the exact
# failure mode this prevents.
_ISOLATED_CONTEXT_PLAYERS = {"session_after_logout"}


async def _local_authenticated_context(
    session_manager: "SessionManager", session_pool: "SessionPool", role: str, target_url: str,
) -> "BrowserContext":
    """Local equivalent of `VulnModule._authenticated_context` -- same
    underlying `SessionPool`/`SessionManager` calls, no cross-sibling
    import. See module docstring. Falls back to a fresh anonymous
    context for `role == "unauthenticated"` instead of trying (and
    failing) to authenticate a session that was never supposed to
    exist. Also the fallback path when `_fresh_login_context()` isn't
    applicable (non-form_login role, or no login form config)."""
    if role == _UNAUTHENTICATED_ROLE:
        return await session_pool.new_anonymous_context()
    context = await session_pool.get_context(role)
    page = await context.new_page()
    try:
        session = await session_manager.get_session(role, page)
    finally:
        await page.close()
    return await session_pool.apply_session(session, target_url)


async def _fresh_login_context(
    session_pool: "SessionPool",
    user: "UserConfig",
    login_url: str,
    username_selector: "str | list[str] | None",
    password_selector: "str | list[str] | None",
    submit_selector: "str | list[str] | None",
    screenshot_dir: "Path",
) -> tuple["BrowserContext", WalkthroughStep]:
    """Performs a REAL login on a brand-new, isolated `BrowserContext`
    -- see module docstring for why this exists. Returns the context
    (caller owns closing it) plus a reusable `WalkthroughStep`
    capturing the moment login succeeded, for other players to prepend
    as their own opening step."""
    context = await session_pool.new_anonymous_context()
    page = await context.new_page()
    try:
        await page.goto(login_url, timeout=_LOGIN_TIMEOUT_MS)
        username_sel = await _resolve(page, username_selector, GENERIC_USERNAME_SELECTORS)
        password_sel = await _resolve(page, password_selector, GENERIC_PASSWORD_SELECTORS)
        submit_sel = await _resolve(page, submit_selector, GENERIC_SUBMIT_SELECTORS)
        if username_sel is None or password_sel is None or submit_sel is None:
            raise RuntimeError(f"could not locate a login form field on {login_url}")

        await page.fill(username_sel, user.username)
        await page.fill(password_sel, user.password)
        try:
            await page.click(submit_sel)
        except Exception:
            await page.click(submit_sel, force=True)

        with contextlib.suppress(Exception):
            await page.wait_for_url(lambda url: url.rstrip("/") != login_url.rstrip("/"), timeout=_LOGIN_TIMEOUT_MS)

        directory = screenshot_dir / f"_login_{user.role}"
        shot_path: str | None = None
        try:
            path = await screenshot_module.capture(page, output_dir=directory, label="step_1_logged_in")
            shot_path = str(path)
        except Exception:
            shot_path = None
        login_step = WalkthroughStep(
            order=1, caption=f"Log in as '{user.username}' (role: {user.role})", screenshot_path=shot_path,
        )
    finally:
        await page.close()
    return context, login_step


async def _resolve(page, configured: "str | list[str] | None", fallback: list[str]) -> str | None:
    candidates = [configured] if isinstance(configured, str) else (configured or fallback)
    for candidate in candidates:
        try:
            if await page.locator(candidate).count() > 0:
                return candidate
        except Exception:  # noqa: S112 -- best-effort selector probing, same pattern as form_login._first_matching
            continue
    return None


def _walkthrough_title(finding: "Finding") -> str:
    return finding.vuln_type


class _RoleContextCache:
    """One fresh, logged-in context per role for the duration of the
    walkthrough build -- login happens once per role, reused across
    that role's findings (deliberate: speed + consistency, per plan).
    Owns closing every context it created via `close_all()`."""

    def __init__(
        self, session_manager: "SessionManager", session_pool: "SessionPool", users_by_role: "dict[str, UserConfig]",
        login_url: str, username_selector, password_selector, submit_selector, screenshot_dir: "Path",
    ) -> None:
        self._session_manager = session_manager
        self._session_pool = session_pool
        self._users_by_role = users_by_role
        self._login_url = login_url
        self._username_selector = username_selector
        self._password_selector = password_selector
        self._submit_selector = submit_selector
        self._screenshot_dir = screenshot_dir
        self._cache: "dict[str, tuple[BrowserContext, WalkthroughStep | None]]" = {}

    # Read-only passthrough so `_build_one()` can hand the SAME real,
    # configured login_url/selectors down into every player call
    # (players need these directly -- e.g. login_form_injection must
    # navigate to the real login PAGE, not a finding's POST-action URL;
    # see that player's own docstring).
    @property
    def login_url(self) -> str:
        return self._login_url

    @property
    def username_selector(self):
        return self._username_selector

    @property
    def password_selector(self):
        return self._password_selector

    @property
    def submit_selector(self):
        return self._submit_selector

    async def get(self, role: str, target_url: str) -> "tuple[BrowserContext, WalkthroughStep | None]":
        if role in self._cache:
            return self._cache[role]
        if role == _UNAUTHENTICATED_ROLE:
            context = await self._session_pool.new_anonymous_context()
            entry = (context, None)
            self._cache[role] = entry
            return entry

        user = self._users_by_role.get(role)
        if user is not None and user.auth_type == "form_login" and self._login_url:
            try:
                context, login_step = await _fresh_login_context(
                    self._session_pool, user, self._login_url,
                    self._username_selector, self._password_selector, self._submit_selector,
                    self._screenshot_dir,
                )
                entry = (context, login_step)
                self._cache[role] = entry
                return entry
            except Exception as exc:
                _log.warning(f"fresh login for role '{role}' failed, falling back to the scan's own session: {exc}")

        context = await _local_authenticated_context(self._session_manager, self._session_pool, role, target_url)
        entry = (context, None)
        self._cache[role] = entry
        return entry

    async def get_isolated(self, role: str) -> "tuple[BrowserContext, WalkthroughStep | None]":
        """A fresh, standalone login -- NEVER cached, NEVER shared with
        `.get()`'s per-role cache. For players that deliberately mutate
        real session state (e.g. a real logout) -- reusing the shared
        cache for those would silently log out every OTHER finding
        under the same role for the rest of the walkthrough build (the
        exact bug this exists to prevent; see `_ISOLATED_CONTEXT_
        PLAYERS` in `_build_one`). Caller owns closing the returned
        context."""
        user = self._users_by_role.get(role)
        if user is not None and user.auth_type == "form_login" and self._login_url:
            return await _fresh_login_context(
                self._session_pool, user, self._login_url,
                self._username_selector, self._password_selector, self._submit_selector,
                self._screenshot_dir,
            )
        context = await _local_authenticated_context(self._session_manager, self._session_pool, role, self._login_url or "")
        return context, None

    async def close_all(self) -> None:
        """Closes every context this cache created (isolated contexts
        are the caller's own responsibility, not tracked here)."""
        for context, _login_step in self._cache.values():
            with contextlib.suppress(Exception):
                await context.close()


def _renumbered(steps: list[WalkthroughStep], offset: int) -> list[WalkthroughStep]:
    return [dataclasses.replace(s, order=s.order + offset) for s in steps]


async def _build_one(
    finding: "Finding", session_manager: "SessionManager", session_pool: "SessionPool", screenshot_dir: "Path",
    role_cache: "_RoleContextCache",
) -> FindingWalkthrough:
    walkthrough = FindingWalkthrough(
        finding_id=finding.finding_id,
        tc_id=display_tc_id(finding),
        title=_walkthrough_title(finding),
        severity=finding.severity,
        endpoint_url=finding.endpoint.url,
        impact_summary=finding.description,
        remediation=finding.recommendation,
    )

    player_name = classify_finding(finding)
    player = PLAYERS[player_name]
    isolated = player_name in _ISOLATED_CONTEXT_PLAYERS

    page = None
    isolated_context = None
    try:
        if isolated:
            # Never touches the shared per-role cache -- this player
            # performs a REAL logout, which would otherwise silently
            # log out every other finding still to be replayed under
            # the same role for the rest of this build (the exact bug
            # this isolation exists to prevent).
            isolated_context, login_step = await role_cache.get_isolated(finding.user_role)
            context = isolated_context
        else:
            context, login_step = await role_cache.get(finding.user_role, finding.endpoint.url)
        page = await context.new_page()
        steps = await asyncio.wait_for(
            player(
                page, context, finding, finding.user_role, session_manager, session_pool, screenshot_dir,
                login_url=role_cache.login_url, username_selector=role_cache.username_selector,
                password_selector=role_cache.password_selector, submit_selector=role_cache.submit_selector,
            ),
            timeout=_PLAYER_TIMEOUT_S,
        )
        if login_step is not None and player_name in _PREPEND_LOGIN_STEP_PLAYERS:
            steps = [dataclasses.replace(login_step, order=1), *_renumbered(steps, offset=1)]
        walkthrough.steps = steps
    except asyncio.TimeoutError:
        walkthrough.build_error = (
            f"replay timed out after {_PLAYER_TIMEOUT_S:.0f}s using the '{player_name}' player"
        )
        _log.warning(f"walkthrough timeout for finding {finding.finding_id} ({player_name})")
    except Exception as exc:
        walkthrough.build_error = f"replay failed using the '{player_name}' player: {exc}"
        _log.warning(f"walkthrough build failed for finding {finding.finding_id} ({player_name}): {exc}")
    finally:
        if page is not None:
            # best-effort cleanup only -- never let a close() failure mask the real result
            with contextlib.suppress(Exception):
                await page.close()
        if isolated_context is not None:
            with contextlib.suppress(Exception):
                await isolated_context.close()

    return walkthrough


async def build_walkthroughs(
    findings: list["Finding"],
    session_manager: "SessionManager",
    session_pool: "SessionPool",
    scan_id: str,
    screenshot_base_dir: "str | Path" = "data/evidence",
    progress: "ProgressCallback | None" = None,
    login_url: str = "",
    username_selector: "str | list[str] | None" = None,
    password_selector: "str | list[str] | None" = None,
    submit_selector: "str | list[str] | None" = None,
    users_by_role: "dict[str, UserConfig] | None" = None,
) -> list[FindingWalkthrough]:
    """Builds one `FindingWalkthrough` per FAIL finding in `findings`.

    `findings` is the caller's already-filtered `list[Finding]` --
    `extract_findings()` (Layer 9's `modules/results.py`) only ever
    produces `Finding` objects for confirmed FAILs to begin with (never
    PASS/SKIP/ERROR), so this is filtering defensively, not because a
    non-FAIL `Finding` is expected to appear in practice.

    `login_url`/`*_selector`/`users_by_role` (all already in scope at
    `main.py`'s call site via `config.target.*`/`load_users()`) drive
    `_fresh_login_context()` -- see module docstring. Omitting them
    (e.g. from existing test callers) degrades gracefully to the old
    shared-scan-session replay path, never a hard error.

    Runs sequentially, not concurrently -- deliberate: players share
    browser contexts per role via `session_pool`, and one finding's
    replay problem must never take down the others (each is isolated
    inside `_build_one`'s own try/except, matching this codebase's
    per-test isolation rule)."""
    from pathlib import Path

    screenshot_dir = Path(screenshot_base_dir) / scan_id / "walkthrough"
    total = len(findings)
    walkthroughs: list[FindingWalkthrough] = []
    role_cache = _RoleContextCache(
        session_manager, session_pool, users_by_role or {},
        login_url, username_selector, password_selector, submit_selector, screenshot_dir,
    )

    try:
        for i, finding in enumerate(findings):
            if progress is not None:
                progress(i, total, f"finding {finding.finding_id}")
            walkthrough = await _build_one(finding, session_manager, session_pool, screenshot_dir, role_cache)
            walkthroughs.append(walkthrough)
    finally:
        await role_cache.close_all()

    if progress is not None:
        progress(total, total, "walkthrough build complete")

    return walkthroughs
