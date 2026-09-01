"""Layer 4 — Form Login auth provider (Phase 1).

Navigates to the login page, fills credentials from `users.json`,
submits, waits for a success signal, and captures the resulting cookies
into a `Session`.

Lesson learned the hard way while validating Layer 3B: a login form
that silently re-renders on bad credentials doesn't raise any error by
itself, so a caller relying on "no exception" to mean "login succeeded"
gets fooled. `success_selector` (an element/text that only appears once
truly logged in) is the reliable signal; the URL-change fallback used
when it's omitted is a best-effort heuristic, not a guarantee.

Real bug found and fixed here (confirmed against `data/stof.db` after
hours of elapsed wall-clock time between `stof test` runs): this used
to leave `Session.expires_at` as `None`. Layer 5's `needs_refresh()`
treats `expires_at is None` as "never expires," so once a session was
cached, `SessionManager` would keep reusing its cookies forever, even
long after the *target's own* server-side session (JSESSIONID) had
timed out. Symptom: `stof test` silently returning 0 findings with no
error at all -- the server was quietly treating every request as
unauthenticated (serving a uniform "please log in" page for every
probe), which looks identical to "no IDOR here" unless you compare
against a fresh login. JWT sessions never had this problem because
`JWTAuthProvider` derives a real `expires_at` from the token's `exp`
claim; form-based auth has no equivalent claim to read, so this
provider now sets a conservative, configurable default instead of
leaving it unset.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from stof.core.logger import get_logger
from stof.session.models import Session

from .base import AuthExpiredError, AuthFailedError, AuthProvider

if TYPE_CHECKING:
    from playwright.async_api import Page

    from stof.config.schema import UserConfig

_log = get_logger("auth.form_login")

# Conservative: most app-server default session timeouts (e.g. Tomcat's
# default is 30 minutes) are longer than this, so re-authenticating a
# little early just means one extra login, not a functional problem --
# far cheaper than silently trusting a cookie the target has already
# expired server-side (see module docstring).
DEFAULT_SESSION_LIFETIME = timedelta(minutes=15)

# App-agnostic fallback selectors, tried in order, for targets that
# don't set `TargetConfig.*_selector` explicitly. No single CSS
# selector matches every login form, so these are candidate *lists* --
# `_first_matching()` below picks whichever one the current page
# actually has, rather than assuming one target's specific DOM.
#
# Known failure mode, live-verified: `_first_matching()` only checks
# "does at least one element match this selector anywhere on the
# page" -- it has no notion of "within the same <form>". A page with
# more than one form using generic markup (e.g. a header search box
# AND a login form, each with their own `input[type='text']` /
# `input[type='submit']`) can make the broadest fallback candidate
# match a field from the WRONG form. Confirmed on a real target: the
# last-resort `input[type='text']` matched a search box that appeared
# before the actual username field in DOM order, so "admin" got typed
# into search instead of the login form, and the search form's submit
# button (also matched generically) fired instead of the login
# button -- `authenticate()` returned no error at all, it just quietly
# logged in as nobody. There is no generic fix for this (the fallback
# selectors are inherently page-agnostic); `TargetConfig.username_
# selector`/`password_selector`/`submit_selector` explicitly set to
# that target's real field selectors is the correct, supported way
# out once the generic fallback picks the wrong element.
GENERIC_USERNAME_SELECTORS = [
    "input[type='email']",
    "input[name='email']",
    "#email",
    "input[name='username']",
    "#username",
    "input[autocomplete='username']",
    "input[autocomplete='email']",
    "input[type='text']",
]
GENERIC_PASSWORD_SELECTORS = [
    "input[type='password']",
    "#password",
    "input[name='password']",
]
GENERIC_SUBMIT_SELECTORS = [
    "button[type='submit']",
    "input[type='submit']",
    "button:has-text('Log in')",
    "button:has-text('Sign in')",
    "button:has-text('Login')",
]

# Best-effort dismissal of first-load overlays (cookie consent, GDPR
# banners, welcome dialogs) that intercept clicks on the underlying
# form -- confirmed live: a real target's own welcome-banner overlay
# blocked every click attempt on its login button for the entire retry
# window, since Playwright correctly refuses to click through an
# element another node is intercepting pointer events for. Generic
# candidates covering common patterns, not any one target's specific
# banner; a page with none of these just has nothing to dismiss.
GENERIC_OVERLAY_DISMISS_SELECTORS = [
    "#cookieconsent-container button",
    "#onetrust-accept-btn-handler",
    "[aria-label='Close Welcome Banner']",
    "[aria-label='dismiss cookie message']",
    "[aria-label='Close']",
    "button:has-text('Accept All')",
    "button:has-text('I Accept')",
    "button:has-text('Accept')",
    "button:has-text('Got it')",
    "button:has-text('Dismiss')",
]


async def _dismiss_overlays(page: "Page", selectors: list[str] = GENERIC_OVERLAY_DISMISS_SELECTORS) -> None:
    """Never raises: an overlay that doesn't exist on this page is not
    a failure, and a dismiss click that itself fails shouldn't block
    login -- the fill/click calls that follow will surface a real
    problem on their own if the page genuinely isn't interactable."""
    for selector in selectors:
        try:
            locator = page.locator(selector)
            if await locator.count() > 0:
                await locator.first.click(timeout=1500)
        except Exception:
            continue


async def _first_matching(page: "Page", selectors: str | list[str], purpose: str) -> str:
    """Returns the first selector in `selectors` that actually matches
    an element on the current page. Accepts a single selector too (a
    target that set an explicit `TargetConfig.*_selector` shouldn't pay
    for candidate probing)."""
    candidates = [selectors] if isinstance(selectors, str) else selectors
    for candidate in candidates:
        try:
            if await page.locator(candidate).count() > 0:
                return candidate
        except Exception:
            continue
    raise AuthFailedError(f"no {purpose} field found on the login page (tried: {candidates})")


async def _form_scope_selector(page: "Page", element_selector: str) -> str | None:
    """Returns a CSS selector uniquely identifying the `<form>` ancestor
    of the element `element_selector` matches, or `None` if it has no
    `<form>` ancestor (some SPAs render inputs outside any `<form>` tag
    -- nothing to scope to, callers fall back to page-wide matching,
    exactly like before this existed).

    This is the generic, app-agnostic fix for the multi-form false-match
    failure mode documented in this module's docstring: scoping the
    username/submit candidate search to the SAME form as the password
    field stops a page with more than one form (e.g. a header search
    box using equally-generic markup) from matching the wrong one --
    without needing that target's own selectors configured by hand.
    Tags the actual form DOM node with a unique marker attribute rather
    than guessing an nth-of-type/index selector, which can silently
    resolve to the wrong form when several forms share a parent."""
    try:
        marker = f"stof-scope-{uuid.uuid4().hex[:8]}"
        return await page.eval_on_selector(
            element_selector,
            "(el, marker) => { "
            "const form = el.closest('form'); "
            "if (!form) return null; "
            "form.setAttribute('data-stof-scope', marker); "
            "return '[data-stof-scope=\"' + marker + '\"]'; "
            "}",
            marker,
        )
    except Exception:
        return None


async def _first_matching_scoped(
    page: "Page", scope_selector: str | None, selectors: str | list[str], purpose: str
) -> str:
    """Like `_first_matching()`, but when `scope_selector` is set, tries
    each candidate scoped to that form FIRST -- as one combined CSS
    selector string, so `page.fill(selector, ...)`/`page.click(selector)`
    call sites don't need to change shape -- falling back to the
    original page-wide candidates if nothing matched within scope (a
    field genuinely outside the `<form>` tag is a real, if unusual,
    pattern some SPAs use)."""
    if scope_selector:
        candidates = [selectors] if isinstance(selectors, str) else selectors
        scoped = [f"{scope_selector} {c}" for c in candidates]
        try:
            return await _first_matching(page, scoped, purpose)
        except AuthFailedError:
            pass
    return await _first_matching(page, selectors, purpose)


class FormLoginProvider(AuthProvider):
    """`login_url`/selectors describe the target's login form. Phase 1's
    `UserConfig` schema (Layer 1) only has id/role/username/password/
    auth_type -- no form-selector fields -- so these are constructor
    args supplied by whoever wires the provider up, not invented fields
    on a Layer 1 contract this module doesn't own."""

    def __init__(
        self,
        login_url: str,
        username_selector: str | list[str] = GENERIC_USERNAME_SELECTORS,
        password_selector: str | list[str] = GENERIC_PASSWORD_SELECTORS,
        submit_selector: str | list[str] = GENERIC_SUBMIT_SELECTORS,
        success_selector: str | list[str] | None = None,
        timeout_ms: int = 10000,
        session_lifetime: timedelta = DEFAULT_SESSION_LIFETIME,
    ) -> None:
        self._login_url = login_url
        self._username_selector = username_selector
        self._password_selector = password_selector
        self._submit_selector = submit_selector
        self._success_selector = success_selector
        self._timeout_ms = timeout_ms
        self._session_lifetime = session_lifetime

    async def authenticate(self, user: "UserConfig", page: "Page") -> Session:
        await page.goto(self._login_url)
        await _dismiss_overlays(page)
        # Password field first: it's the most reliable anchor for "which
        # form is the login form" (nearly every real page has exactly
        # one, unlike the broader username/submit candidates which can't
        # tell one <input type=text> from another on their own) -- see
        # `_form_scope_selector()`'s docstring for the failure mode this
        # scoping fixes.
        password_sel = await _first_matching(page, self._password_selector, "password")
        form_scope = await _form_scope_selector(page, password_sel)
        username_sel = await _first_matching_scoped(page, form_scope, self._username_selector, "username/email")
        submit_sel = await _first_matching_scoped(page, form_scope, self._submit_selector, "submit button")
        await page.fill(username_sel, user.username)
        await page.fill(password_sel, user.password)
        try:
            await page.click(submit_sel)
        except Exception:
            # A persistent decorative overlay (e.g. a "fork me on
            # GitHub" corner ribbon, confirmed live) can occupy the
            # same bounding box as the real button without visually
            # covering it -- Playwright correctly refuses a normal
            # click since another element would receive the pointer
            # event there. `force=True` bypasses that actionability
            # check; safe here since `_first_matching` already
            # confirmed this selector is the real submit control.
            await page.click(submit_sel, force=True)

        if self._success_selector is not None:
            candidates = [self._success_selector] if isinstance(self._success_selector, str) else self._success_selector
            found = False
            last_exc: Exception | None = None
            for candidate in candidates:
                try:
                    await page.wait_for_selector(candidate, timeout=self._timeout_ms)
                    found = True
                    break
                except Exception as exc:
                    last_exc = exc
            if not found:
                raise AuthFailedError(
                    f"login failed for user '{user.id}': none of the success selectors "
                    f"{candidates!r} appeared: {last_exc}"
                ) from last_exc
        else:
            # No success_selector configured -- a real login form nearly
            # always navigates away from its own login URL on success
            # (including client-routed SPAs), so waiting for that is a
            # generic, app-agnostic signal. Deliberately not
            # `wait_for_load_state("networkidle")`: confirmed against a
            # real target that keeps background network activity alive
            # indefinitely (e.g. periodic polling), which made
            # "networkidle" hang for the full timeout on every login.
            try:
                await page.wait_for_url(
                    lambda url: url.rstrip("/") != self._login_url.rstrip("/"), timeout=self._timeout_ms
                )
            except Exception as exc:
                raise AuthFailedError(
                    f"login failed for user '{user.id}': still on the login page after submit "
                    "(no success_selector configured to confirm otherwise)"
                ) from exc

        cookies = await self._extract_cookies(page)
        expires_at = datetime.now(timezone.utc) + self._session_lifetime
        session = Session(user_id=user.id, role=user.role, auth_type="form_login", cookies=cookies, expires_at=expires_at)
        _log.info(f"authenticated user '{user.id}' (role={user.role}) via form_login, expires_at={expires_at}")
        return session

    async def refresh(self, session: Session, page: "Page") -> Session:
        # Form-based sessions have no refresh endpoint to call -- the
        # session manager is expected to authenticate() from scratch.
        raise AuthExpiredError(
            f"form_login session {session.session_id} cannot be refreshed in place; "
            "re-authenticate from scratch"
        )

    async def is_authenticated(self, session: Session, page: "Page") -> bool:
        if not session.is_valid:
            return False
        current_cookies = await self._extract_cookies(page)
        return all(current_cookies.get(name) == value for name, value in session.cookies.items())

    async def _extract_cookies(self, page: "Page") -> dict[str, str]:
        raw_cookies = await page.context.cookies()
        return {cookie["name"]: cookie["value"] for cookie in raw_cookies}
