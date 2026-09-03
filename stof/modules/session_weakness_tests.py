"""TC-129 -- Session / rate-limit weakness techniques, a mixin composed
into `AuthTestsModule` -- same precedent as `bfla_tests.py`/`role_tests.py`
mixing into `IdorTestsModule` (see that module's own docstring for the
full reasoning). CLAUDE.md's own Layer 9 file list already scopes
"session fixation, brute, lockout" to `auth_tests.py`; this file is that
scope, kept as its own module for readability without giving it a
second module identity or config flag -- it rides on the existing
`auth_tests: true` flag, same as `bfla_tests.py`/`role_tests.py` ride on
`idor_tests: true`.

Three techniques:

- TC-129.1 -- Session identifier not regenerated on login (classic
  session fixation): captures a cookie from a fresh anonymous context,
  forces a real fresh login for the configured test role, and compares
  same-named cookie values across that boundary.
- TC-129.2 -- Session remains valid after logout: captures the session
  cookie from a fresh login, triggers logout (a configured
  `AuthTestConfig.logout_url`, or a generic logout-link/button click on
  the target page -- same "optional override + generic app-agnostic
  fallback" convention `stof.auth.form_login`'s own selector lists
  use), then replays the OLD cookie against the target -- a still-
  authenticated response is the finding.
- TC-129.3 -- No rate limiting / lockout on login: a small, bounded
  (`_RATE_LIMIT_ATTEMPT_COUNT`, within the 5-8 range the safety
  boundary calls for) number of wrong-credential login attempts, each
  against a distinct made-up username -- deliberately never the real
  configured test account, so this probe can never itself lock out the
  account every other technique in this scan depends on. Reuses
  `authorization.decision.classify_response()`'s existing HTTP 429 ->
  CHALLENGED mapping rather than hand-rolling a new one, plus a small
  CAPTCHA/lockout-message keyword check for targets that signal
  throttling without a 429.

- TC-129.4 -- Session remains valid after a password change:
  architecturally identical to TC-129.2's plant/verify shape (capture
  cookie -> trigger event -> replay old cookie), just triggered by a
  real password-change request instead of a logout -- the disclosed
  "Breaking the Competition" (HackerOne) pattern in `session_knowledge_
  base.json`: developers who correctly invalidate sessions on logout
  frequently forget that a password change carries the identical "kill
  every other session" obligation. This is a real, gated write (a
  password change) -- gated behind `AuthTestConfig.
  allow_state_changing_probes`, same convention as every write-verb
  technique in `auth_tests.py` (TC-025.1-5, TC-027.4-5), and reuses
  `AuthTestsModule._change_password()`/`_confirm_password_works()`
  directly rather than re-implementing the POST shape -- this mixin is
  composed INTO `AuthTestsModule` (not a sibling import), so `self.
  _change_password` is already the same method TC-027.4/TC-025.* call.
  The password is changed to a temporary probe value and reverted back
  to the original in a `finally` block, exactly like every other
  password-changing technique in this codebase.

- TC-129.5 -- Session/auth cookie missing security flags: reuses the
  exact same anon-context-vs-fresh-login-context cookie-diffing
  primitive as TC-129.1 (`_force_fresh_login`), but keeps the raw
  Playwright cookie dicts (not just name:value) since the flags being
  checked -- `httpOnly`, `secure`, `sameSite` -- live there. Only
  cookies that are NEW or CHANGED across that same login boundary are
  in scope (never every cookie on the site -- the OWASP Session
  Management Cheat Sheet's own scoping, and this project's existing
  precedent for identifying "the session/auth cookie" without a
  brittle name-pattern guess). `SameSite` missing entirely is
  deliberately NOT a finding (modern browsers already default to
  `Lax`); only `SameSite=None` set explicitly without `Secure` is
  flagged, per real disclosed reports (HackerOne #5204, #239380,
  #7033 for missing `HttpOnly`; #343928 for missing `Secure`) --
  `HttpOnly` is checked first as the highest-confidence signal.

Both TC-129.1 and TC-129.2 need a REAL, fresh login to observe a cookie-
issuance event -- `SessionManager.get_session()`'s normal caching (one
Session per role, reused until near expiry) would otherwise just hand
back a session authenticated minutes ago. `SessionManager.invalidate()`
is that class's own public, documented hook for forcing exactly this
("forcing re-authentication on the next get_session() call") -- using
it here is not a structural change to Layer 5, just exercising the API
it already exposes for this purpose. TC-129.2 also invalidates the
role's cached session once it has actually triggered a real logout, so
no other module/technique in this scan keeps trusting a session the
target itself just terminated server-side. TC-129.4 does the same once
it has changed the password back to its original value.

Every finding's description states only the observed signal (a cookie
value match, an HTTP status/classification, the presence/absence of a
429-or-CAPTCHA-shaped response) -- never a claim that the underlying
account was actually taken over or damaged, per this project's own
Finding-description convention.

Three further techniques, added in a later wave (session timeout /
concurrent sessions / token entropy -- see `session_knowledge_base.json`
for the full research behind each):

- TC-129.6 -- Session timeout / expiry not observable or unbounded:
  actually waiting out a real idle/absolute timeout window live inside
  a bounded scan is impractical, so this is a deliberately honest
  structural check, not a fabricated live-wait test. It forces a real
  fresh login and inspects the resulting `Session.expires_at` (already
  part of the Layer 5 data contract) against `Session.created_at`.
  SKIPs cleanly -- never a false PASS/FAIL -- when the target exposes
  no expiry information STOF can observe at all.
- TC-129.7 -- Concurrent sessions are not revoked on a second login:
  two real logins for the same role via `_force_fresh_login` (called
  twice), then a replay of the FIRST session's cookies after the
  SECOND login completes -- architecturally the same plant/verify
  shape as TC-129.2/TC-129.4, just triggered by a second real login
  rather than a logout or password change. No new payload and no
  `allow_state_changing_probes` gating: a second real login is the
  same non-destructive class of action as the rest of this module.
- TC-129.8 -- Session token low entropy / predictable structure: purely
  observational analysis of the SAME-named session cookie's value
  captured across two independent fresh logins for the same role
  (reusing the two logins TC-129.7 already performs the mechanism
  for) -- flags a short value, a long shared prefix across two
  independently-issued tokens, a small numeric difference between two
  purely-numeric tokens, or very low character-set variety. Never
  attempts to guess or brute-force another user's session -- both
  values it compares come from this module's own two logins.

Two further techniques, closing tracker gaps TC-049 and TC-107:

- TC-129.9 -- Back/refresh cache weakness (tracker TC-049): a real,
  fresh login followed by a single authenticated GET, checking whether
  the response's Cache-Control header includes `no-store`/`no-cache`.
  A missing directive on an authenticated HTML page means a shared or
  public browser's back-button/disk cache can replay that page's
  content even after logout -- WSTG's own "Testing for Browser Cache
  Weaknesses" check, structurally simpler and more honestly testable
  than actually driving a real browser Back button click, which
  observes the identical underlying HTTP-caching contract.
- TC-129.10 -- Rate limiting on password-reset requests (tracker
  TC-107): TC-129.3's exact bounded-attempt-count / lockout-signal
  shape, retargeted at `AuthTestConfig.reset_password_request_url`
  (already a config field this module's host class, `AuthTestsModule`,
  exposes for TC-027's own password-reset techniques) instead of the
  login endpoint -- the real gap TC-107 in the tracker names: rate
  limiting frequently only covers login, leaving password-reset/OTP
  endpoints open to spam or enumeration at scale. SKIPs cleanly when
  no such endpoint is configured -- there is no generic, safe way to
  auto-discover "the sensitive non-login endpoint" from crawl data
  alone.
"""
from __future__ import annotations

import json as json_module
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from stof.authorization.decision import AuthorizationDecision, classify_response
from stof.core.logger import get_logger
from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding

from ._injection_shared import placeholder_value, send_probe
from .base import _PASSWORD_FIELD_HINTS, _USERNAME_FIELD_HINTS, find_login_endpoint
from .results import FAIL, PASS, SKIPPED, TestCaseResult

if TYPE_CHECKING:
    from stof.engine.multi_session import SessionPool
    from stof.session.session_manager import SessionManager

_log = get_logger("modules.session_weakness_tests")

# Bounded per the safety boundary: this is a shared live demo target,
# not a throwaway local one -- 5-8 attempts is enough to observe
# whether ANY throttling kicks in, without functioning as a real
# brute-force/DoS run. No artificial delay is added either way; the
# only pacing that exists is whatever the target itself imposes.
_RATE_LIMIT_ATTEMPT_COUNT = 6

_LOCKOUT_SIGNAL_MARKERS: tuple[str, ...] = (
    "captcha", "recaptcha", "too many attempts", "too many requests", "try again later",
    "account locked", "account is locked", "temporarily locked", "temporarily disabled",
    "rate limit", "slow down",
)

# Generic, app-agnostic logout-link/button candidates -- same
# "candidate list, first match wins" philosophy as `stof.auth.
# form_login`'s GENERIC_*_SELECTORS, including AltoroMutual's own
# "Sign Off" wording alongside the far more common "Logout"/"Sign Out".
_GENERIC_LOGOUT_SELECTORS: tuple[str, ...] = (
    "a:has-text('Log Out')", "a:has-text('Logout')", "a:has-text('Log out')",
    "a:has-text('Sign Out')", "a:has-text('Sign out')",
    "a:has-text('Sign Off')", "a:has-text('Sign off')",
    "a:has-text('Log Off')", "a:has-text('Log off')",
    "button:has-text('Logout')", "button:has-text('Log Out')",
    "button:has-text('Sign Out')", "button:has-text('Sign Off')",
    "[href*='logout' i]", "[href*='signoff' i]", "[href*='sign-off' i]",
    "#logout", ".logout",
)


def _synthetic_endpoint(url: str, method: str) -> Endpoint:
    """Same small local copy `auth_tests.py` itself keeps -- a
    `Finding`/evidence needs an `Endpoint`, but the URLs this file
    probes (a discovered endpoint URL, a configured login endpoint)
    aren't necessarily ones a technique already has an `Endpoint`
    object for."""
    return Endpoint(url=url, method=method, endpoint_type="api", auth_required=False)


def _cookies_to_playwright(cookies: dict[str, str], url: str) -> list[dict]:
    """Same shape as `engine.multi_session._to_playwright_cookies` --
    duplicated locally rather than imported: Layer 9 modules don't
    reach into Layer 3B's own leading-underscore internals, the same
    boundary this project already draws elsewhere (`_idor_shared.py`'s
    docstring, `auth_tests.py`'s own re-implemented `_extract_token`)."""
    domain = urlsplit(url).hostname or ""
    return [{"name": name, "value": value, "domain": domain, "path": "/"} for name, value in cookies.items()]


def _session_cookie_did_not_rotate(anon_cookies: dict[str, str], authenticated_cookies: dict[str, str]) -> str | None:
    """Returns the name of the first cookie that kept an identical
    value across the login boundary -- the session-fixation signal --
    or `None` if every shared cookie name's value changed (or there
    was no shared name at all, meaning there was nothing to fixate)."""
    for name, anon_value in anon_cookies.items():
        if authenticated_cookies.get(name) == anon_value:
            return name
    return None


def _new_or_changed_cookies(anon_cookies: list[dict], authenticated_cookies: list[dict]) -> dict[str, dict]:
    """TC-129.5's version of `_session_cookie_did_not_rotate`'s own
    diff, kept as full raw Playwright cookie dicts (name/value/httpOnly/
    secure/sameSite/...) rather than collapsed to name:value -- the
    flag checks below need the flags. Returns the post-login cookie
    for every name that is either absent from the pre-login jar or
    carries a different value there: the same "new or changed across
    the login boundary" gate that identifies a session/auth cookie
    without guessing from its name."""
    anon_by_name = {c["name"]: c for c in anon_cookies}
    changed: dict[str, dict] = {}
    for cookie in authenticated_cookies:
        name = cookie["name"]
        prior = anon_by_name.get(name)
        if prior is None or prior.get("value") != cookie.get("value"):
            changed[name] = cookie
    return changed


def _cache_control_issue(content_type: str, cache_control: str | None) -> str | None:
    """Pure, directly-unit-testable check for TC-129.9 (back/refresh
    cache weakness, tracker id TC-049): an authenticated HTML response
    that omits both `no-store` and `no-cache` from Cache-Control lets a
    shared/public browser's back-button or disk cache replay sensitive
    content after the user has logged out -- WSTG's own "Testing for
    Browser Cache Weaknesses" check. Only applies to HTML responses
    (never flags a JSON/API/static-asset response, which legitimately
    has different caching needs); `None` on a clean response or a
    non-HTML content-type."""
    if "text/html" not in content_type.lower():
        return None
    directive = (cache_control or "").lower()
    if "no-store" in directive or "no-cache" in directive:
        return None
    return "authenticated response has no Cache-Control: no-store/no-cache directive"


def _cookie_flag_issue(cookie: dict, is_https_target: bool) -> str | None:
    """Pure, directly-unit-testable flag check for a single session/auth
    cookie (already identified as new-or-changed by
    `_new_or_changed_cookies`). Checked in priority order per the
    research -- `HttpOnly` first as the highest-confidence signal,
    `Secure` next (only meaningful to check on an https:// target --
    an http:// target has no Secure cookie to demand), then the
    `SameSite=None`-without-`Secure` combination. `SameSite` missing
    entirely is deliberately NOT checked at all here -- modern browsers
    already default it to `Lax`, so flagging its mere absence would be
    a false positive the research specifically warned against."""
    name = cookie.get("name", "")
    if not cookie.get("httpOnly", False):
        return f"cookie '{name}' is missing the HttpOnly flag"
    if is_https_target and not cookie.get("secure", False):
        return f"cookie '{name}' is missing the Secure flag on an https:// target"
    if cookie.get("sameSite") == "None" and not cookie.get("secure", False):
        return f"cookie '{name}' sets SameSite=None without also setting the Secure flag"
    return None


# --- TC-129.6 pure helper: session timeout / expiry observability -------

# OWASP's own Session Management Cheat Sheet guidance is a 4-8 hour
# absolute timeout for a typical full-working-day usage pattern.
# Chosen deliberately generous (a multiple of that upper bound, not a
# tight match to it) so this never flags a legitimate longer-lived
# session as a false positive -- the goal is catching "effectively no
# timeout at all", not second-guessing a target's specific policy.
_TIMEOUT_UNBOUNDED_THRESHOLD = timedelta(hours=24)


def _session_timeout_issue(created_at: datetime, expires_at: datetime) -> str | None:
    """Pure, directly-unit-testable check: is the observed expiry span
    consistent with SOME bounded timeout being enforced? Only called
    once `expires_at` is known to be non-None -- the "no expiry
    observable at all" case is a SKIP handled directly in the
    technique, not a finding this helper can produce."""
    span = expires_at - created_at
    if span > _TIMEOUT_UNBOUNDED_THRESHOLD:
        hours = span.total_seconds() / 3600
        return (
            f"the session's observed expiry is {hours:.1f} hours from issuance, far beyond "
            "OWASP's ~4-8 hour absolute-timeout guidance -- no meaningful session timeout appears to be enforced"
        )
    return None


# --- TC-129.8 pure helper: session token entropy/predictability ---------


def _token_entropy_issue(value_a: str, value_b: str) -> str | None:
    """Pure, directly-unit-testable analysis of the SAME-named session
    cookie's value captured across two independent fresh logins.
    Identical values are deliberately NOT flagged here -- that's
    TC-129.1's session-fixation finding, a different root cause and a
    different vuln_type; double-reporting it here would be noise, not
    a second real signal."""
    if not value_a or not value_b or value_a == value_b:
        return None

    shorter = min(len(value_a), len(value_b))
    if shorter < 16:
        return f"the token is only {shorter} characters long (under 16), suggesting insufficient entropy"

    # Checked before the generic shared-prefix check: a realistic
    # sequential/incrementing numeric identifier (e.g. a DB auto-
    # increment counter) naturally ALSO shares a long prefix for large
    # values, so the more specific, more actionable "sequential" signal
    # takes priority over the more generic "shared prefix" one.
    if value_a.isdigit() and value_b.isdigit():
        diff = abs(int(value_a) - int(value_b))
        if diff < 1000:
            return (
                f"tokens are purely numeric and differ by only {diff} between two independent logins, "
                "suggesting a sequential/incrementing identifier"
            )

    common_prefix_len = 0
    for char_a, char_b in zip(value_a, value_b, strict=False):
        if char_a != char_b:
            break
        common_prefix_len += 1
    if common_prefix_len >= 8 and common_prefix_len >= shorter * 0.5:
        return (
            f"two independently-issued tokens for this cookie share an identical {common_prefix_len}-character "
            "prefix, suggesting a predictable/non-random component"
        )

    distinct_chars = len(set(value_a))
    if distinct_chars <= 4:
        return f"the token uses only {distinct_chars} distinct character(s), suggesting low character-set entropy"

    return None


async def _click_first_logout_link(page) -> bool:
    """Best-effort: tries each candidate selector in order, clicking
    the first one actually present on the page. Never raises -- a
    selector that doesn't match, or a click that fails for an
    unrelated reason, just means "try the next candidate", same
    tolerance `stof.auth.form_login._dismiss_overlays` already uses
    for its own best-effort DOM interaction."""
    for selector in _GENERIC_LOGOUT_SELECTORS:
        try:
            locator = page.locator(selector)
            if await locator.count() > 0:
                await locator.first.click(timeout=2000)
                return True
        except Exception as exc:
            _log.debug(f"logout selector '{selector}' didn't match/click: {exc}")
            continue
    return False


def _form_login_fields(endpoint: Endpoint) -> tuple[str, str] | None:
    """Same small local copy `auth_tests.py` itself keeps -- the
    (username_param, password_param) pair on a discovered HTML login
    form, found generically by field-name hint rather than assuming
    this target's own naming. Duplicated rather than imported: this
    mixin is composed INTO `AuthTestsModule` (`auth_tests.py` imports
    this file), so `auth_tests.py` importing this helper back would be
    circular."""
    username_param = next((p for p in endpoint.parameters if any(h in p.lower() for h in _USERNAME_FIELD_HINTS)), None)
    password_param = next((p for p in endpoint.parameters if any(h in p.lower() for h in _PASSWORD_FIELD_HINTS)), None)
    if username_param is None or password_param is None:
        return None
    return username_param, password_param


async def _attempt_wrong_form_login(context, endpoint: Endpoint, username_param: str, password_param: str, username: str, password: str) -> tuple[int, str]:
    """Form-encoded counterpart to `_attempt_wrong_login`, for TC-129.3's
    fallback against a discovered HTML login form rather than a
    configured JSON login endpoint."""
    params = {n: placeholder_value(n) for n in endpoint.parameters}
    params[username_param] = username
    params[password_param] = password
    probe = await send_probe(context, endpoint, params, endpoint.location_for(username_param))
    if probe is None:
        return 0, ""
    status, body, _elapsed, _headers = probe
    return status, body


async def _attempt_wrong_login(context, url: str, username: str, password: str) -> tuple[int, str]:
    """Deliberately narrower than `auth_tests.py`'s own `_try_json_login`:
    TC-129.3 never needs to know whether a credential pair *succeeded*
    (it always sends a wrong password), only the raw (status, body) of
    each attempt to check for a throttling signal -- so this stays a
    small local helper rather than importing `auth_tests.py`'s function,
    which would create a circular import (`auth_tests.py` imports this
    file's mixin to compose into `AuthTestsModule`)."""
    try:
        resp = await context.request.post(
            url,
            data=json_module.dumps({"username": username, "email": username, "password": password}),
            headers={"Content-Type": "application/json"},
        )
        return resp.status, await resp.text()
    except Exception as exc:
        return 0, str(exc)


class SessionWeaknessTechniquesMixin:
    async def _force_fresh_login(self, session_manager: "SessionManager", session_pool: "SessionPool", role: str, target_url: str):
        """See module docstring: forces a real, fresh `authenticate()`
        call via `SessionManager`'s own public `invalidate()` hook,
        instead of silently reusing a session cached minutes earlier."""
        session_manager.invalidate(role)
        return await self._authenticated_context(session_manager, session_pool, role, target_url)

    # --- TC-129.1 Session ID doesn't rotate on login ---------------------

    async def _technique_session_id_no_rotation(self, endpoints, session_manager, session_pool, evidence) -> TestCaseResult:
        test_id, tid = "TC-129", "TC-129.1"
        technique = "Session identifier is not regenerated on login (session fixation)"
        vuln_type = "Session Fixation (No Session Rotation on Login)"
        role = self.config.test_role
        if not role:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no test_role configured for this target")
        # `login_json_endpoint`/`change_password_url` are config-only and
        # frequently unset for a classic form-based target (confirmed
        # live: demo.testfire.net has neither, which used to SKIP this
        # entirely even though 68 crawled endpoints were available) --
        # falling back to a discovered endpoint, same as TC-129.2 already
        # does, lets this run against any target the crawler reached at
        # all, not only ones with a JSON login/change-password API.
        target_url = self.config.login_json_endpoint or self.config.change_password_url or (endpoints[0].url if endpoints else None)
        if not target_url:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no target URL available to probe (login_json_endpoint/change_password_url/discovered endpoint)")

        anon_context = await session_pool.new_anonymous_context()
        try:
            probe = await self._probe_get(anon_context, target_url)
            if probe is None:
                return self._result(test_id, tid, technique, vuln_type, "ERROR", f"could not reach '{target_url}' to observe the pre-login cookie state")
            raw_cookies = await anon_context.cookies()
            anon_cookies = {c["name"]: c["value"] for c in raw_cookies}
        finally:
            await anon_context.close()

        try:
            session, _context = await self._force_fresh_login(session_manager, session_pool, role, target_url)
        except KeyError as exc:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        authenticated_cookies = dict(session.cookies)
        if not authenticated_cookies:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 f"role '{role}' session carries no cookies at all (non-cookie-based auth, e.g. JWT) -- session-fixation-via-cookie doesn't apply")

        fixated_cookie = _session_cookie_did_not_rotate(anon_cookies, authenticated_cookies)
        if fixated_cookie is None:
            if not anon_cookies:
                detail = f"no cookie was issued prior to authentication -- {len(authenticated_cookies)} cookie(s) issued at login, nothing to fixate"
            else:
                detail = f"{len(anon_cookies)} pre-login cookie(s) observed; none kept the same value after login (session identifier rotates correctly)"
            return self._result(test_id, tid, technique, vuln_type, PASS, detail)

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.1,
            endpoint=_synthetic_endpoint(target_url, "GET"), user_role=role,
            request_raw=f"GET {target_url} (anonymous, pre-login) vs. an authenticated session for role '{role}'",
            response_raw=f"cookie '{fixated_cookie}' value unchanged across the login boundary",
            description=(
                f"The '{fixated_cookie}' cookie kept an identical value across the login boundary "
                f"for role '{role}' -- the server does not regenerate the session identifier on "
                "authentication, letting an attacker who fixes a victim's pre-login cookie value "
                "hijack the resulting authenticated session."
            ),
            recommendation="Regenerate the session identifier (issue a brand-new session cookie) immediately after successful authentication, and invalidate the pre-login one.",
        )
        finding.evidence_refs = await self._capture(evidence, finding)
        return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)

    # --- TC-129.2 Session remains valid after logout ----------------------

    async def _trigger_logout(self, context, target_url: str) -> bool:
        page = None
        try:
            page = await context.new_page()
            if self.config.logout_url:
                try:
                    await page.goto(self.config.logout_url, timeout=10000)
                    return True
                except Exception as exc:
                    _log.warning(f"configured logout_url navigation failed: {exc}")
                    return False
            try:
                await page.goto(target_url, timeout=10000)
            except Exception as exc:
                _log.warning(f"navigation to '{target_url}' before the logout attempt failed: {exc}")
            return await _click_first_logout_link(page)
        finally:
            if page is not None:
                await page.close()

    async def _technique_session_valid_after_logout(self, endpoints, session_manager, session_pool, evidence) -> TestCaseResult:
        test_id, tid = "TC-129", "TC-129.2"
        technique, vuln_type = "Session cookie remains valid after logout", "Session Not Invalidated On Logout"
        role = self.config.test_role
        if not role:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no test_role configured for this target")
        target_url = endpoints[0].url if endpoints else self.config.login_json_endpoint
        if not target_url:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no discovered endpoint / configured URL available to probe")

        try:
            session, context = await self._force_fresh_login(session_manager, session_pool, role, target_url)
        except KeyError as exc:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        old_cookies = dict(session.cookies)
        if not old_cookies:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 f"role '{role}' session carries no cookies at all (non-cookie-based auth) -- nothing to replay")

        logged_out = await self._trigger_logout(context, target_url)
        if not logged_out:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 "no logout mechanism found -- set AuthTestConfig.logout_url, or this target has no generic logout link/button this technique recognizes")

        try:
            replay_context = await session_pool.new_anonymous_context()
            try:
                await replay_context.add_cookies(_cookies_to_playwright(old_cookies, target_url))
                probe = await self._probe_get(replay_context, target_url)
            finally:
                await replay_context.close()
        finally:
            # A real logout was just triggered -- the cached Session for
            # this role is now genuinely stale server-side. Force the
            # next module/technique that needs this role to re-
            # authenticate instead of silently trusting a session the
            # target itself just terminated.
            session_manager.invalidate(role)

        if probe is None:
            return self._result(test_id, tid, technique, vuln_type, "ERROR", "could not replay the pre-logout session cookie (probe request failed)")
        status, body = probe
        decision = classify_response(status, body)
        if decision == AuthorizationDecision.ALLOWED:
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
                endpoint=_synthetic_endpoint(target_url, "GET"), user_role=role,
                request_raw=f"GET {target_url} using the session cookie captured before logout for role '{role}'",
                response_raw=f"HTTP {status}, {len(body)} bytes (post-logout replay)",
                description=(
                    f"The session cookie captured for role '{role}' before triggering logout still "
                    f"authenticates against '{target_url}' afterward (HTTP {status}), meaning the "
                    "server does not invalidate the session server-side on logout."
                ),
                recommendation="Invalidate the session server-side (not just client-side cookie clearing) the instant a user logs out, so a previously-captured cookie can no longer be replayed.",
            )
            finding.evidence_refs = await self._capture(evidence, finding)
            return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        return self._result(test_id, tid, technique, vuln_type, PASS,
                             f"replaying the pre-logout session cookie against '{target_url}' after logout returned HTTP {status} ({decision.value}) -- session was correctly invalidated")

    # --- TC-129.3 No rate limiting / lockout on login ----------------------

    async def _technique_no_rate_limiting(self, endpoints, session_pool) -> TestCaseResult:
        test_id, tid = "TC-129", "TC-129.3"
        technique = "No rate limiting or lockout across repeated failed login attempts"
        vuln_type = "Missing Login Rate Limiting / Account Lockout"
        login_url = self.config.login_json_endpoint

        login_endpoint = None
        fields = None
        if not login_url:
            # No JSON-API login endpoint configured -- fall back to the
            # crawler's own discovered HTML login form (`find_login_endpoint`,
            # `base.py`), same fallback treatment as TC-022.1/TC-027.5
            # for the identical recurring JSON-login-only gap.
            login_endpoint = find_login_endpoint(endpoints)
            if login_endpoint is None:
                return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                     "no JSON login endpoint configured (target.jwt_token_url), and no discovered "
                                     "HTML login form to fall back to")
            fields = _form_login_fields(login_endpoint)
            if fields is None:
                return self._result(test_id, tid, technique, vuln_type, SKIPPED, "discovered login form is missing an expected username/password field")

        probe_target = login_endpoint.url if login_endpoint is not None else login_url
        anon_context = await session_pool.new_anonymous_context()
        try:
            status, body = 0, ""
            for attempt in range(1, _RATE_LIMIT_ATTEMPT_COUNT + 1):
                # A distinct, made-up username per attempt -- never the
                # real configured test account -- so this probe can
                # never itself lock out the account every other
                # technique in this scan depends on. Per-IP rate
                # limiting, the far more common real-world control, is
                # still fully exercised this way.
                username = f"stof-ratelimit-probe-{attempt}@example.invalid"
                if login_endpoint is not None:
                    username_param, password_param = fields
                    status, body = await _attempt_wrong_form_login(anon_context, login_endpoint, username_param, password_param, username, "WrongPassword!123")
                else:
                    status, body = await _attempt_wrong_login(anon_context, login_url, username, "WrongPassword!123")
                decision = classify_response(status, body)
                if decision == AuthorizationDecision.CHALLENGED or any(marker in body.lower() for marker in _LOCKOUT_SIGNAL_MARKERS):
                    return self._result(test_id, tid, technique, vuln_type, PASS,
                                         f"a rate-limiting/lockout signal (HTTP {status}, or a CAPTCHA/lockout-shaped response) appeared after {attempt} failed attempt(s)")
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
                endpoint=(login_endpoint or _synthetic_endpoint(login_url, "POST")), user_role="unauthenticated",
                request_raw=f"{_RATE_LIMIT_ATTEMPT_COUNT}x POST {probe_target} (distinct made-up usernames, wrong passwords each time)",
                response_raw=f"HTTP {status} on every attempt, no 429/CAPTCHA/lockout signal observed",
                description=(
                    f"{_RATE_LIMIT_ATTEMPT_COUNT} consecutive failed login attempts against "
                    f"'{probe_target}' produced no HTTP 429, CAPTCHA, or lockout-shaped response -- "
                    "the endpoint has no observable rate limiting or account lockout protection."
                ),
                recommendation="Apply progressive delays, a CAPTCHA challenge, or account/IP lockout after a small number of consecutive failed login attempts.",
            )
            return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        finally:
            await anon_context.close()

    # --- TC-129.4 Session remains valid after a password change -----------

    async def _technique_session_valid_after_password_change(self, endpoints, session_manager, session_pool, evidence) -> TestCaseResult:
        test_id, tid = "TC-129", "TC-129.4"
        technique = "Session cookie remains valid after a password change"
        vuln_type = "Session Not Invalidated On Password Change"
        if not self.config.allow_state_changing_probes:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 "changes the test account's real password and is disabled by default -- "
                                 "set AuthTestConfig.allow_state_changing_probes=True for an authorized engagement window")
        role = self.config.test_role
        if not (self.config.change_password_url and role and self.config.test_current_password):
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 "no change_password_url / test_role / test_current_password configured for this target")

        try:
            session, context = await self._force_fresh_login(session_manager, session_pool, role, self.config.change_password_url)
        except KeyError as exc:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        old_cookies = dict(session.cookies)
        if not old_cookies:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 f"role '{role}' session carries no cookies at all (non-cookie-based auth) -- nothing to replay")

        target_url = endpoints[0].url if endpoints else self.config.login_json_endpoint
        if not target_url:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no discovered endpoint / configured URL available to probe")

        original = self.config.test_current_password
        probe_password = "TempSessionProbe!73"
        # Reuses `AuthTestsModule._change_password()` directly -- this
        # mixin is composed INTO `AuthTestsModule`, so `self` already is
        # that class instance (not a sibling-module import).
        accepted, status = await self._change_password(context, probe_password, original)
        if not accepted:
            return self._result(test_id, tid, technique, vuln_type, "ERROR",
                                 f"could not trigger a real password change to test with (change-password request returned HTTP {status})")

        try:
            confirmed = await self._confirm_password_works(context, probe_password)
            if confirmed is False:
                return self._result(test_id, tid, technique, vuln_type, PASS,
                                     f"change-password request returned HTTP {status}, but logging in with the new "
                                     "password failed -- the password wasn't actually changed, so there's nothing to test")

            try:
                replay_context = await session_pool.new_anonymous_context()
                try:
                    await replay_context.add_cookies(_cookies_to_playwright(old_cookies, target_url))
                    probe = await self._probe_get(replay_context, target_url)
                finally:
                    await replay_context.close()
            finally:
                # A real password change was just triggered -- the cached
                # Session for this role is now stale (the credential it
                # was authenticated with has moved on). Force the next
                # module/technique that needs this role to re-authenticate
                # instead of silently trusting a session captured before
                # the change, same as TC-129.2 does after a real logout.
                session_manager.invalidate(role)

            if probe is None:
                return self._result(test_id, tid, technique, vuln_type, "ERROR", "could not replay the pre-change session cookie (probe request failed)")
            probe_status, body = probe
            decision = classify_response(probe_status, body)
            if decision == AuthorizationDecision.ALLOWED:
                finding = Finding(
                    module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
                    endpoint=_synthetic_endpoint(target_url, "GET"), user_role=role,
                    request_raw=f"GET {target_url} using the session cookie captured before a password change for role '{role}'",
                    response_raw=f"HTTP {probe_status}, {len(body)} bytes (post-password-change replay)",
                    description=(
                        f"The session cookie captured before a password change still authenticates afterward "
                        f"against '{target_url}' (HTTP {probe_status}), meaning the server does not invalidate "
                        "other active sessions when the account's password is changed."
                    ),
                    recommendation="Invalidate every other active session server-side the instant a password change succeeds, not just the session that performed the change.",
                )
                finding.evidence_refs = await self._capture(evidence, finding)
                return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)
            return self._result(test_id, tid, technique, vuln_type, PASS,
                                 f"replaying the pre-change session cookie against '{target_url}' after the password change returned "
                                 f"HTTP {probe_status} ({decision.value}) -- other sessions were correctly invalidated")
        finally:
            reverted, revert_status = await self._change_password(context, original, probe_password)
            if not reverted:
                _log.error(
                    f"COULD NOT REVERT test account '{self.config.test_username}' password after the "
                    f"session-valid-after-password-change probe (HTTP {revert_status}) -- it may now be '{probe_password}'. Manual intervention required."
                )

    # --- TC-129.5 Session/auth cookie missing security flags --------------

    async def _technique_cookie_security_flags(self, endpoints, session_manager, session_pool, evidence) -> TestCaseResult:
        test_id, tid = "TC-129", "TC-129.5"
        technique = "Session/auth cookie missing HttpOnly, Secure, or safe SameSite flags"
        vuln_type = "Session Cookie Missing Security Flags"
        role = self.config.test_role
        if not role:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no test_role configured for this target")
        # Same target-URL fallback chain as TC-129.1, for the same reason
        # (a classic form-based target frequently has neither
        # login_json_endpoint nor change_password_url configured).
        target_url = self.config.login_json_endpoint or self.config.change_password_url or (endpoints[0].url if endpoints else None)
        if not target_url:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no target URL available to probe (login_json_endpoint/change_password_url/discovered endpoint)")

        anon_context = await session_pool.new_anonymous_context()
        try:
            probe = await self._probe_get(anon_context, target_url)
            if probe is None:
                return self._result(test_id, tid, technique, vuln_type, "ERROR", f"could not reach '{target_url}' to observe the pre-login cookie state")
            anon_cookies = await anon_context.cookies()
        finally:
            await anon_context.close()

        try:
            _session, context = await self._force_fresh_login(session_manager, session_pool, role, target_url)
        except KeyError as exc:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        authenticated_cookies = await context.cookies()
        new_or_changed = _new_or_changed_cookies(anon_cookies, authenticated_cookies)
        if not new_or_changed:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 f"no cookie was newly issued or changed value across the login boundary for role '{role}' -- "
                                 "no session/auth cookie identified (e.g. a non-cookie-based auth target)")

        is_https_target = urlsplit(target_url).scheme == "https"
        for name in sorted(new_or_changed):
            issue = _cookie_flag_issue(new_or_changed[name], is_https_target)
            if issue is None:
                continue
            cookie = new_or_changed[name]
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=5.3,
                endpoint=_synthetic_endpoint(target_url, "GET"), user_role=role,
                request_raw=f"GET {target_url} (anonymous, pre-login) vs. a freshly-authenticated session for role '{role}'",
                response_raw=f"cookie '{name}': httpOnly={cookie.get('httpOnly')}, secure={cookie.get('secure')}, sameSite={cookie.get('sameSite')!r}",
                description=(
                    f"{issue} -- identified as a session/auth cookie because it was newly issued or changed "
                    f"value across the login boundary for role '{role}'."
                ),
                recommendation="Set HttpOnly and Secure on every session/auth cookie, and never set SameSite=None without also setting Secure.",
            )
            finding.evidence_refs = await self._capture(evidence, finding)
            return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        return self._result(test_id, tid, technique, vuln_type, PASS,
                             f"{len(new_or_changed)} session/auth cookie(s) newly issued/changed at login for role '{role}' all carry the correct security flags")

    # --- TC-129.6 Session timeout / expiry not observable or unbounded ----

    async def _technique_session_timeout(self, session_manager, session_pool) -> TestCaseResult:
        test_id, tid = "TC-129", "TC-129.6"
        technique = "Session timeout/expiry is not observable or is unbounded"
        vuln_type = "Session Timeout Not Enforced or Not Observable"
        role = self.config.test_role
        if not role:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no test_role configured for this target")
        target_url = self.config.login_json_endpoint or self.config.change_password_url
        if not target_url:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 "no login_json_endpoint/change_password_url configured to force a fresh login against")

        try:
            session, _context = await self._force_fresh_login(session_manager, session_pool, role, target_url)
        except KeyError as exc:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        if session.expires_at is None:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 f"no expiry information observable on role '{role}''s session (no JWT exp claim / "
                                 "Set-Cookie Max-Age / token-endpoint expiry STOF could read) -- actually waiting out "
                                 "a real timeout window live is impractical for a bounded scan, so this cannot be "
                                 "honestly tested for this target")

        issue = _session_timeout_issue(session.created_at, session.expires_at)
        if issue is None:
            span_hours = (session.expires_at - session.created_at).total_seconds() / 3600
            return self._result(test_id, tid, technique, vuln_type, PASS,
                                 f"role '{role}''s session carries an observable expiry {span_hours:.1f} hours from "
                                 "issuance, consistent with a bounded timeout being enforced")

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Low", cvss_score=3.1,
            endpoint=_synthetic_endpoint(target_url, "GET"), user_role=role,
            request_raw=f"fresh authentication for role '{role}' against '{target_url}'",
            response_raw=f"Session.created_at={session.created_at.isoformat()}, Session.expires_at={session.expires_at.isoformat()}",
            description=issue,
            recommendation="Enforce a bounded idle timeout (2-30 minutes depending on application risk) and an absolute session timeout (typically 4-8 hours), per the OWASP Session Management Cheat Sheet.",
        )
        return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)

    # --- TC-129.9 Back/refresh cache weakness (tracker id TC-049) ---------

    async def _technique_cache_control_weakness(self, endpoints, session_manager, session_pool) -> TestCaseResult:
        test_id, tid = "TC-129", "TC-129.9"
        technique = "Authenticated response missing no-store/no-cache Cache-Control (back/refresh cache weakness)"
        vuln_type = "Sensitive Content Cacheable After Logout (Back/Refresh Attack)"
        role = self.config.test_role
        if not role:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no test_role configured for this target")
        target_url = endpoints[0].url if endpoints else self.config.login_json_endpoint
        if not target_url:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no discovered endpoint / configured URL available to probe")

        try:
            _session, context = await self._force_fresh_login(session_manager, session_pool, role, target_url)
        except KeyError as exc:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        try:
            resp = await context.request.get(target_url, max_redirects=0)
        except Exception as exc:
            return self._result(test_id, tid, technique, vuln_type, "ERROR", f"probe failed: {exc}")
        headers = {k.lower(): v for k, v in resp.headers.items()}
        content_type = headers.get("content-type", "")
        cache_control = headers.get("cache-control")
        issue = _cache_control_issue(content_type, cache_control)
        if issue is None:
            return self._result(test_id, tid, technique, vuln_type, PASS,
                                 f"authenticated response from '{target_url}' (Content-Type: {content_type or 'unknown'}) "
                                 f"correctly sets Cache-Control: {cache_control!r}")

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Low", cvss_score=3.7,
            endpoint=_synthetic_endpoint(target_url, "GET"), user_role=role,
            request_raw=f"GET {target_url} (authenticated, role '{role}')",
            response_raw=f"Content-Type: {content_type}\nCache-Control: {cache_control}",
            description=(
                f"'{target_url}' {issue} -- a shared or public browser's back-button/disk cache can "
                "replay this authenticated page's content even after the user has logged out."
            ),
            recommendation="Set Cache-Control: no-store (and Pragma: no-cache for older HTTP/1.0 caches) on every authenticated response.",
        )
        return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)

    # --- TC-129.10 Rate limiting on password-reset request (tracker id TC-107) ---

    async def _technique_reset_endpoint_rate_limiting(self, session_pool) -> TestCaseResult:
        test_id, tid = "TC-129", "TC-129.10"
        technique = "No rate limiting across repeated password-reset requests"
        vuln_type = "Missing Rate Limiting On Sensitive Non-Login Endpoint"
        reset_url = self.config.reset_password_request_url
        if not reset_url:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 "no reset_password_request_url configured for this target -- no sensitive "
                                 "non-login endpoint this technique can generically discover to probe")

        anon_context = await session_pool.new_anonymous_context()
        try:
            status, body = 0, ""
            for attempt in range(1, _RATE_LIMIT_ATTEMPT_COUNT + 1):
                email = f"stof-ratelimit-reset-{attempt}@example.invalid"
                try:
                    resp = await anon_context.request.post(
                        reset_url, data=json_module.dumps({"email": email, "username": email}),
                        headers={"Content-Type": "application/json"},
                    )
                    status, body = resp.status, await resp.text()
                except Exception as exc:
                    status, body = 0, str(exc)
                decision = classify_response(status, body)
                if decision == AuthorizationDecision.CHALLENGED or any(marker in body.lower() for marker in _LOCKOUT_SIGNAL_MARKERS):
                    return self._result(test_id, tid, technique, vuln_type, PASS,
                                         f"a rate-limiting/lockout signal (HTTP {status}, or a CAPTCHA/lockout-shaped response) appeared after {attempt} request(s)")
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=5.3,
                endpoint=_synthetic_endpoint(reset_url, "POST"), user_role="unauthenticated",
                request_raw=f"{_RATE_LIMIT_ATTEMPT_COUNT}x POST {reset_url} (distinct made-up email addresses)",
                response_raw=f"HTTP {status} on every attempt, no 429/CAPTCHA/lockout signal observed",
                description=(
                    f"{_RATE_LIMIT_ATTEMPT_COUNT} consecutive password-reset requests against '{reset_url}' "
                    "produced no HTTP 429, CAPTCHA, or lockout-shaped response -- this sensitive endpoint has "
                    "no observable rate limiting, enabling mass password-reset-email spam or account enumeration at scale."
                ),
                recommendation="Apply per-IP and/or per-account rate limiting to password-reset (and similarly sensitive OTP/verification) endpoints, not just the login endpoint.",
            )
            return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        finally:
            await anon_context.close()

    # --- TC-129.7 Concurrent sessions are not revoked on a second login ---

    async def _technique_concurrent_session_not_revoked(self, endpoints, session_manager, session_pool) -> TestCaseResult:
        test_id, tid = "TC-129", "TC-129.7"
        technique = "Prior session remains valid after a second login for the same account"
        vuln_type = "Concurrent Session Not Revoked On Re-Login"
        role = self.config.test_role
        if not role:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no test_role configured for this target")
        target_url = endpoints[0].url if endpoints else self.config.login_json_endpoint
        if not target_url:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no discovered endpoint / configured URL available to probe")

        try:
            first_session, _first_context = await self._force_fresh_login(session_manager, session_pool, role, target_url)
        except KeyError as exc:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        first_cookies = dict(first_session.cookies)
        if not first_cookies:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 f"role '{role}' session carries no cookies at all (non-cookie-based auth) -- nothing to replay")

        try:
            await self._force_fresh_login(session_manager, session_pool, role, target_url)
        except KeyError as exc:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        replay_context = await session_pool.new_anonymous_context()
        try:
            await replay_context.add_cookies(_cookies_to_playwright(first_cookies, target_url))
            probe = await self._probe_get(replay_context, target_url)
        finally:
            await replay_context.close()

        if probe is None:
            return self._result(test_id, tid, technique, vuln_type, "ERROR",
                                 "could not replay the first session's cookie after the second login (probe request failed)")
        status, body = probe
        decision = classify_response(status, body)
        if decision == AuthorizationDecision.ALLOWED:
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=5.9,
                endpoint=_synthetic_endpoint(target_url, "GET"), user_role=role,
                request_raw=f"GET {target_url} using the FIRST of two independent logins' session cookie for role '{role}', after the second login completed",
                response_raw=f"HTTP {status}, {len(body)} bytes (post-second-login replay)",
                description=(
                    f"The session cookie captured from a first login for role '{role}' still authenticates against "
                    f"'{target_url}' (HTTP {status}) after a second, independent login for the same role has "
                    "completed -- the server does not revoke prior sessions when a new one is established."
                ),
                recommendation="Either revoke prior sessions when a new authentication event occurs for the same account, or provide the user a way to view and remotely terminate concurrent sessions, per the OWASP Session Management Cheat Sheet.",
            )
            return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        return self._result(test_id, tid, technique, vuln_type, PASS,
                             f"replaying the first session's cookie against '{target_url}' after a second login returned "
                             f"HTTP {status} ({decision.value}) -- the prior session was correctly revoked")

    # --- TC-129.8 Session token low entropy / predictable structure -------

    async def _technique_session_token_entropy(self, endpoints, session_manager, session_pool) -> TestCaseResult:
        test_id, tid = "TC-129", "TC-129.8"
        technique = "Session token is low-entropy or predictable across independent logins"
        vuln_type = "Predictable / Low-Entropy Session Token"
        role = self.config.test_role
        if not role:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no test_role configured for this target")
        target_url = endpoints[0].url if endpoints else self.config.login_json_endpoint
        if not target_url:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no discovered endpoint / configured URL available to probe")

        try:
            first_session, _ctx = await self._force_fresh_login(session_manager, session_pool, role, target_url)
            second_session, _ctx2 = await self._force_fresh_login(session_manager, session_pool, role, target_url)
        except KeyError as exc:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        first_cookies, second_cookies = dict(first_session.cookies), dict(second_session.cookies)
        shared_names = sorted(set(first_cookies) & set(second_cookies))
        if not shared_names:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 f"no cookie name observed in both of two independent logins for role '{role}' "
                                 "(non-cookie-based auth, or a name that changes every login) -- nothing to compare")

        for name in shared_names:
            issue = _token_entropy_issue(first_cookies[name], second_cookies[name])
            if issue is None:
                continue
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=6.5,
                endpoint=_synthetic_endpoint(target_url, "GET"), user_role=role,
                request_raw=f"two independent fresh logins for role '{role}', comparing the '{name}' cookie's value each time",
                response_raw=f"cookie '{name}': {issue}",
                description=f"Cookie '{name}' -- {issue}.",
                recommendation="Generate session identifiers with a cryptographically secure PRNG carrying at least 64 bits of entropy, with no fixed, sequential, or otherwise predictable component, per the OWASP Session Management Cheat Sheet.",
            )
            return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        return self._result(test_id, tid, technique, vuln_type, PASS,
                             f"{len(shared_names)} shared session cookie(s) compared across two independent logins for "
                             f"role '{role}'; none showed a low-entropy/predictable pattern")

    # --- TC-129.11 Lockout bypass via spoofed X-Forwarded-For (tracker TC-023) ---

    async def _technique_lockout_bypass_via_xff(self, endpoints, session_pool) -> TestCaseResult:
        test_id, tid = "TC-129", "TC-129.11"
        technique = "Login lockout/rate-limit is bypassable via a spoofed X-Forwarded-For header"
        vuln_type = "Weak Lockout Mechanism (IP-Header Bypass)"
        login_url = self.config.login_json_endpoint
        login_endpoint, fields = None, None
        if not login_url:
            login_endpoint = find_login_endpoint(endpoints)
            if login_endpoint is None:
                return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                     "no JSON login endpoint configured, and no discovered HTML login form to fall back to")
            fields = _form_login_fields(login_endpoint)
            if fields is None:
                return self._result(test_id, tid, technique, vuln_type, SKIPPED, "discovered login form is missing an expected username/password field")

        anon_context = await session_pool.new_anonymous_context()
        try:
            status, body = 0, ""
            triggered = False
            for attempt in range(1, _RATE_LIMIT_ATTEMPT_COUNT + 1):
                username = f"stof-lockout-probe-{attempt}@example.invalid"
                if login_endpoint is not None:
                    username_param, password_param = fields
                    status, body = await _attempt_wrong_form_login(anon_context, login_endpoint, username_param, password_param, username, "WrongPassword!123")
                else:
                    status, body = await _attempt_wrong_login(anon_context, login_url, username, "WrongPassword!123")
                decision = classify_response(status, body)
                if decision == AuthorizationDecision.CHALLENGED or any(marker in body.lower() for marker in _LOCKOUT_SIGNAL_MARKERS):
                    triggered = True
                    break
            if not triggered:
                return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                     f"no rate-limiting/lockout signal appeared within {_RATE_LIMIT_ATTEMPT_COUNT} attempts -- nothing to test "
                                     "bypassing (see TC-129.3 for the missing-rate-limiting finding itself)")

            # Lockout genuinely triggered -- retry the SAME wrong-credential
            # shape once more, this time with a spoofed X-Forwarded-For/
            # X-Real-IP claiming a different origin IP. A server that keys
            # its lockout purely off these attacker-controlled headers
            # (rather than the real connecting IP plus/instead the account
            # identifier) will accept this next attempt without a
            # challenge -- proving the lockout is bypassable, not that the
            # spoofed credential pair itself succeeded.
            spoofed_ip = "203.0.113.77"  # TEST-NET-3 (RFC 5737) -- never a real routable address
            probe_username = "stof-lockout-probe-bypass@example.invalid"
            if login_endpoint is not None:
                username_param, password_param = fields
                params = {n: placeholder_value(n) for n in login_endpoint.parameters}
                params[username_param] = probe_username
                params[password_param] = "WrongPassword!123"
                probe = await send_probe(anon_context, login_endpoint, params, login_endpoint.location_for(username_param),
                                          extra_headers={"X-Forwarded-For": spoofed_ip, "X-Real-IP": spoofed_ip})
                bypass_status, bypass_body = (probe[0], probe[1]) if probe else (0, "")
            else:
                try:
                    resp = await anon_context.request.post(
                        login_url, data=json_module.dumps({"username": probe_username, "email": probe_username, "password": "WrongPassword!123"}),
                        headers={"Content-Type": "application/json", "X-Forwarded-For": spoofed_ip, "X-Real-IP": spoofed_ip},
                    )
                    bypass_status, bypass_body = resp.status, await resp.text()
                except Exception as exc:
                    bypass_status, bypass_body = 0, str(exc)

            bypass_decision = classify_response(bypass_status, bypass_body)
            still_challenged = bypass_decision == AuthorizationDecision.CHALLENGED or any(marker in bypass_body.lower() for marker in _LOCKOUT_SIGNAL_MARKERS)
            if still_challenged:
                return self._result(test_id, tid, technique, vuln_type, PASS,
                                     f"lockout triggered after real attempts and remained in effect (HTTP {bypass_status}) even with a spoofed "
                                     "X-Forwarded-For/X-Real-IP header -- lockout is not keyed off attacker-controlled IP headers alone")

            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
                endpoint=(login_endpoint or _synthetic_endpoint(login_url, "POST")), user_role="unauthenticated",
                request_raw=f"POST {(login_endpoint.url if login_endpoint else login_url)}\nX-Forwarded-For: {spoofed_ip}\nX-Real-IP: {spoofed_ip}",
                response_raw=f"HTTP {bypass_status} -- no rate-limiting/lockout signal, after lockout had already triggered without the spoofed header",
                description=(
                    "A login lockout/rate-limit signal was observed after repeated failed attempts, but a follow-up attempt with a spoofed "
                    "X-Forwarded-For/X-Real-IP header was accepted without triggering the same challenge -- the lockout mechanism appears to key "
                    "off an attacker-controlled header rather than (or in addition to) the real connecting IP or account identifier."
                ),
                recommendation="Key rate-limiting/lockout off the real connecting IP (from the trusted proxy layer, never an unvalidated client-supplied header) and/or the account identifier, never a client-controlled header alone.",
            )
            return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        finally:
            await anon_context.close()

    # --- TC-129.12 Rate limiting on authenticated API endpoints (tracker TC-108) ---

    async def _technique_api_token_rate_limiting(self, endpoints, session_manager, session_pool) -> TestCaseResult:
        test_id, tid = "TC-129", "TC-129.12"
        technique = "No rate limiting across repeated authenticated API requests"
        vuln_type = "Missing Rate Limiting At The API/Token Level"
        role = self.config.test_role
        if not role:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no test_role configured for this target")
        api_endpoint = next((e for e in endpoints if e.endpoint_type == "api" and e.method == "GET"), None)
        if api_endpoint is None:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no discovered GET API endpoint to probe")

        try:
            _session, context = await self._authenticated_context(session_manager, session_pool, role, api_endpoint.url)
        except KeyError as exc:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        status, body = 0, ""
        for _attempt in range(1, _RATE_LIMIT_ATTEMPT_COUNT + 1):
            probe = await self._probe_get(context, api_endpoint.url)
            if probe is None:
                continue
            status, body = probe
            decision = classify_response(status, body)
            if decision == AuthorizationDecision.CHALLENGED or any(marker in body.lower() for marker in _LOCKOUT_SIGNAL_MARKERS):
                return self._result(test_id, tid, technique, vuln_type, PASS,
                                     f"a rate-limiting signal (HTTP {status}, or a throttling-shaped response) appeared while repeatedly "
                                     f"calling '{api_endpoint.url}' as an authenticated role '{role}' session")
        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Medium", cvss_score=5.3,
            endpoint=api_endpoint, user_role=role,
            request_raw=f"{_RATE_LIMIT_ATTEMPT_COUNT}x GET {api_endpoint.url} (authenticated, role '{role}')",
            response_raw=f"HTTP {status} on every attempt, no 429/throttling signal observed",
            description=(
                f"{_RATE_LIMIT_ATTEMPT_COUNT} consecutive authenticated requests to '{api_endpoint.url}' produced no HTTP 429 or "
                "throttling-shaped response -- this API endpoint has no observable rate limiting at the authenticated/token level, "
                "beyond whatever login-only limiting TC-129.3 already checks."
            ),
            recommendation="Apply per-token/per-account rate limiting to authenticated API endpoints, not just the unauthenticated login endpoint.",
        )
        return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)

    # --- TC-129.13 Session not bound to client fingerprint (tracker TC-046) ---

    async def _technique_session_not_bound_to_client(self, endpoints, session_manager, session_pool) -> TestCaseResult:
        test_id, tid = "TC-129", "TC-129.13"
        technique = "Session cookie is accepted from a different client fingerprint (User-Agent)"
        vuln_type = "Session Not Bound To Client Fingerprint (Hijacking Risk)"
        role = self.config.test_role
        if not role:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no test_role configured for this target")
        target_url = endpoints[0].url if endpoints else self.config.login_json_endpoint
        if not target_url:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, "no discovered endpoint / configured URL available to probe")

        try:
            session, _context = await self._force_fresh_login(session_manager, session_pool, role, target_url)
        except KeyError as exc:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED, f"role not configured: {exc}")

        cookies = dict(session.cookies)
        if not cookies:
            return self._result(test_id, tid, technique, vuln_type, SKIPPED,
                                 f"role '{role}' session carries no cookies at all (non-cookie-based auth) -- nothing to replay")

        # A different browser/OS entirely -- not just a version bump -- to
        # make this a real fingerprint mismatch, not a coincidental match
        # some UA-sniffing middleware might tolerate.
        _DIFFERENT_UA = "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36"
        replay_context = await session_pool.new_anonymous_context()
        try:
            await replay_context.set_extra_http_headers({"User-Agent": _DIFFERENT_UA})
            await replay_context.add_cookies(_cookies_to_playwright(cookies, target_url))
            probe = await self._probe_get(replay_context, target_url)
        finally:
            await replay_context.close()

        if probe is None:
            return self._result(test_id, tid, technique, vuln_type, "ERROR", "could not replay the session cookie under a different User-Agent (probe request failed)")
        status, body = probe
        decision = classify_response(status, body)
        if decision == AuthorizationDecision.ALLOWED:
            finding = Finding(
                module_id=self.module_id, vuln_type=vuln_type, severity="Low", cvss_score=3.7,
                endpoint=_synthetic_endpoint(target_url, "GET"), user_role=role,
                request_raw=f"GET {target_url} using role '{role}''s session cookie, with a completely different User-Agent (desktop login vs. mobile replay)",
                response_raw=f"HTTP {status}, {len(body)} bytes",
                description=(
                    f"The session cookie for role '{role}' is accepted from a client presenting a completely different User-Agent "
                    "than the one that logged in -- the session is not bound to any client fingerprint, so a stolen cookie alone "
                    "(no other client secret) is sufficient to hijack the session from a different device/browser."
                ),
                recommendation="This is a defense-in-depth gap, not a standalone vulnerability (per-request client-binding is unusual and has real usability tradeoffs) -- consider it alongside session lifetime/rotation controls, not as a required fix on its own.",
            )
            return self._result(test_id, tid, technique, vuln_type, FAIL, finding.description, finding=finding)
        return self._result(test_id, tid, technique, vuln_type, PASS,
                             f"replaying the session cookie under a different User-Agent against '{target_url}' returned HTTP {status} "
                             f"({decision.value}) -- session appears bound to the original client in some way")

    async def _techniques_tc129(self, endpoints, session_manager, session_pool, evidence) -> list[TestCaseResult]:
        return [
            await self._safe_result(
                self._technique_session_id_no_rotation(endpoints, session_manager, session_pool, evidence),
                "TC-129", "TC-129.1", "Session identifier is not regenerated on login (session fixation)",
                "Session Fixation (No Session Rotation on Login)", role=self.config.test_role),
            await self._safe_result(
                self._technique_session_valid_after_logout(endpoints, session_manager, session_pool, evidence),
                "TC-129", "TC-129.2", "Session cookie remains valid after logout",
                "Session Not Invalidated On Logout", role=self.config.test_role),
            await self._safe_result(
                self._technique_no_rate_limiting(endpoints, session_pool),
                "TC-129", "TC-129.3", "No rate limiting or lockout across repeated failed login attempts",
                "Missing Login Rate Limiting / Account Lockout", role=self.config.test_role),
            await self._safe_result(
                self._technique_session_valid_after_password_change(endpoints, session_manager, session_pool, evidence),
                "TC-129", "TC-129.4", "Session cookie remains valid after a password change",
                "Session Not Invalidated On Password Change", role=self.config.test_role),
            await self._safe_result(
                self._technique_cookie_security_flags(endpoints, session_manager, session_pool, evidence),
                "TC-129", "TC-129.5", "Session/auth cookie missing HttpOnly, Secure, or safe SameSite flags",
                "Session Cookie Missing Security Flags", role=self.config.test_role),
            await self._safe_result(
                self._technique_session_timeout(session_manager, session_pool),
                "TC-129", "TC-129.6", "Session timeout/expiry is not observable or is unbounded",
                "Session Timeout Not Enforced or Not Observable", role=self.config.test_role),
            await self._safe_result(
                self._technique_concurrent_session_not_revoked(endpoints, session_manager, session_pool),
                "TC-129", "TC-129.7", "Prior session remains valid after a second login for the same account",
                "Concurrent Session Not Revoked On Re-Login", role=self.config.test_role),
            await self._safe_result(
                self._technique_session_token_entropy(endpoints, session_manager, session_pool),
                "TC-129", "TC-129.8", "Session token is low-entropy or predictable across independent logins",
                "Predictable / Low-Entropy Session Token", role=self.config.test_role),
            await self._safe_result(
                self._technique_cache_control_weakness(endpoints, session_manager, session_pool),
                "TC-129", "TC-129.9", "Authenticated response missing no-store/no-cache Cache-Control (back/refresh cache weakness)",
                "Sensitive Content Cacheable After Logout (Back/Refresh Attack)", role=self.config.test_role),
            await self._safe_result(
                self._technique_reset_endpoint_rate_limiting(session_pool),
                "TC-129", "TC-129.10", "No rate limiting across repeated password-reset requests",
                "Missing Rate Limiting On Sensitive Non-Login Endpoint", role=self.config.test_role),
            await self._safe_result(
                self._technique_lockout_bypass_via_xff(endpoints, session_pool),
                "TC-129", "TC-129.11", "Login lockout/rate-limit is bypassable via a spoofed X-Forwarded-For header",
                "Weak Lockout Mechanism (IP-Header Bypass)", role=self.config.test_role),
            await self._safe_result(
                self._technique_api_token_rate_limiting(endpoints, session_manager, session_pool),
                "TC-129", "TC-129.12", "No rate limiting across repeated authenticated API requests",
                "Missing Rate Limiting At The API/Token Level", role=self.config.test_role),
            await self._safe_result(
                self._technique_session_not_bound_to_client(endpoints, session_manager, session_pool),
                "TC-129", "TC-129.13", "Session cookie is accepted from a different client fingerprint (User-Agent)",
                "Session Not Bound To Client Fingerprint (Hijacking Risk)", role=self.config.test_role),
        ]
