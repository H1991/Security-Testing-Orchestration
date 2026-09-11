"""Layer 9 -- `stof/modules/mfa_tests.py`: MFA/TOTP Security Test Module
(TC-140 Pre-MFA Session Access, TC-141 Response-Manipulation Bypass,
TC-142 Missing Rate Limiting, TC-143 OTP Replay, TC-144 Weak/Static
Code Acceptance -- five separate top-level ids, deliberately, not
`.N` sub-techniques of one id: see `_result()`'s own docstring for why
that distinction matters here.).

STOF's TOTP support (`stof/auth/form_login.py`'s `_maybe_complete_totp`)
answers "can STOF log in through this target's MFA step". This module
answers a different question: "is this target's MFA step actually
secure, or just present". Grounded in two independent sources rather
than invented from first principles -- OWASP WSTG's Multi-Factor
Authentication testing section (WSTG-AUTHN-10/11), and live research
against real, disclosed HackerOne/bug-bounty MFA-bypass reports (the
`false`->`true` / 4xx->200 response-manipulation pattern shows up
across dozens of independent public writeups as the single most common
real-world MFA bug, ahead of brute-force or replay).

Every technique here needs `UserConfig.totp_secret` configured for the
test role -- without a real secret, STOF has no way to generate a VALID
code to contrast against an invalid one, so every technique SKIPs
cleanly (never a forced/fake finding) when it's absent, same convention
`jwt_tests.py` uses for a role with no JWT auth_type.

Deliberately does NOT import from `stof.auth` (CLAUDE.md's own forbidden-
import list: "modules importing from auth"). `_locate_and_fill`/
`_submit_primary_credentials` below are a small, independent, generic
selector-matching implementation -- the same *shape* of logic
`stof/auth/form_login.py`'s `FormLoginProvider` uses, deliberately
duplicated rather than shared, matching this project's own established
"a little duplication is the accepted tradeoff" convention for
Layer-9-must-not-import-Layer-4 (see `auth_tests.py`'s
`_API_KEY_PATTERNS` comment for the same tradeoff made elsewhere).

Every technique drives its OWN fresh, unauthenticated browser context
(`session_pool.new_anonymous_context()`) rather than an already-
authenticated session -- MFA testing is inherently about the login flow
itself, before a normal session exists, which none of this project's
other modules need.

Scope, stated plainly: this is the P0 slice of the much larger MFA
technique catalog documented in `EXPLOIT_COVERAGE.md`'s own MFA section
(bypass, replay, brute-force, response-manipulation, weak-code) --
NOT the full 25-technique OWASP+bug-bounty catalog researched for this
module (recovery-code testing, "remember this device" weaknesses, MFA-
management CSRF/IDOR, email/SMS OTP, WebAuthn/passkeys are real,
documented gaps, intentionally deferred, not silently dropped). Each of
those needs its own target-specific config STOF doesn't yet collect
(a recovery-code UI, a "trust this device" checkbox, a second real
account for cross-user OTP-binding tests) -- built when that config
exists, not guessed at now.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import pyotp

from stof.core.logger import get_logger
from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding

from .base import VulnModule
from .results import FAIL, PASS, SKIPPED, TestCaseResult, extract_findings

if TYPE_CHECKING:
    from playwright.async_api import Page

    from stof.engine.multi_session import SessionPool

_log = get_logger("modules.mfa_tests")

# Deliberately the same small, generic candidate lists `form_login.py`
# uses -- NOT imported from there (see module docstring). Kept short
# and high-signal, same "capped candidate list, not a claim to cover
# every possible app" philosophy as every other generic-selector list
# in this codebase.
_USERNAME_SELECTORS = ("input[type='email']", "input[name='email']", "#email", "input[name='username']", "#username", "input[type='text']")
_PASSWORD_SELECTORS = ("input[type='password']", "#password", "input[name='password']")
_SUBMIT_SELECTORS = ("button[type='submit']", "input[type='submit']", "button:has-text('Log in')", "button:has-text('Sign in')")
_TOTP_SELECTORS = (
    "input[autocomplete='one-time-code']", "input[name*='otp' i]", "input[name*='totp' i]",
    "input[id*='otp' i]", "input[id*='totp' i]", "input[name='code']", "input[name='token']",
)
_OVERLAY_DISMISS_SELECTORS = (
    "#cookieconsent-container button", "#onetrust-accept-btn-handler",
    "[aria-label='Close Welcome Banner']", "[aria-label='dismiss cookie message']",
    "button:has-text('Accept All')", "button:has-text('Accept')", "button:has-text('Dismiss')",
)

# Response-body boolean/status keys real MFA-bypass writeups repeatedly
# name as the client-trusted field an attacker flips false->true (or a
# nested equivalent) -- see this module's own docstring for the
# research this is grounded in, not an invented guess-list.
_TRUST_BOOLEAN_KEYS = ("success", "valid", "verified", "authenticated", "ready", "ok", "otpVerified", "isValid")

# Bounded, small brute-force probe -- proving "no rate limiting after N
# attempts" needs only a handful of attempts, not an actual crack
# attempt; this project's own security-testing conventions (CLAUDE.md's
# "candidate-detect vs. auto-exploit is a deliberate line") rule out
# anything resembling a real brute-force run.
_BRUTE_FORCE_ATTEMPT_COUNT = 8
_RATE_LIMIT_STATUS_HINTS = (429,)
_RATE_LIMIT_BODY_HINTS = ("too many", "rate limit", "locked", "try again later", "temporarily blocked")


@dataclass
class MfaTestConfig:
    login_url: str | None = None
    test_username: str | None = None
    test_password: str | None = None
    totp_secret: str | None = None
    test_role: str | None = None
    # A crawler-discovered, `auth_required=True` endpoint to probe for
    # TC-140.1 (pre-MFA privileged access) -- reuses whatever the
    # crawler already found rather than asking for new target-specific
    # config. `None` means TC-140.1 SKIPs (no candidate to probe)
    # rather than guessing a path.


async def _dismiss_overlays(page: "Page") -> None:
    for selector in _OVERLAY_DISMISS_SELECTORS:
        try:
            locator = page.locator(selector)
            if await locator.count() > 0:
                await locator.first.click(timeout=1200)
        except Exception:  # noqa: S112 -- same non-fatal-probe pattern as form_login.py's own `_dismiss_overlays`: a candidate that isn't present isn't a failure
            continue


async def _find_selector(page: "Page", candidates: tuple[str, ...], timeout_ms: int = 4000) -> str | None:
    import asyncio
    import time

    deadline = time.monotonic() + timeout_ms / 1000
    while True:
        for candidate in candidates:
            try:
                if await page.locator(candidate).count() > 0:
                    return candidate
            except Exception:  # noqa: S112 -- a candidate selector that errors just isn't present on this page; the next candidate or the deadline handles it
                continue
        if time.monotonic() >= deadline:
            return None
        await asyncio.sleep(0.25)


async def _submit_primary_credentials(page: "Page", login_url: str, username: str, password: str) -> None:
    """Navigates to the login page and submits username/password only
    -- stops right at the boundary every technique in this module needs
    to test from: primary credentials accepted, MFA step not yet
    completed."""
    await page.goto(login_url, wait_until="domcontentloaded")
    await _dismiss_overlays(page)
    user_sel = await _find_selector(page, _USERNAME_SELECTORS)
    pass_sel = await _find_selector(page, _PASSWORD_SELECTORS)
    if user_sel is None or pass_sel is None:
        raise RuntimeError(f"no username/password field found on {login_url}")
    await page.fill(user_sel, username)
    await page.fill(pass_sel, password)
    submit_sel = await _find_selector(page, _SUBMIT_SELECTORS)
    if submit_sel is None:
        raise RuntimeError(f"no submit button found on {login_url}")
    await page.click(submit_sel)
    await page.wait_for_timeout(1500)


class MfaTestsModule(VulnModule):
    module_id = "mfa_tests"
    name = "MFA / TOTP Security Tests"
    phase = 1

    def __init__(self, config: MfaTestConfig | None = None) -> None:
        self.config = config or MfaTestConfig()

    async def run(self, endpoints, session_manager, session_pool, evidence=None) -> list[Finding]:
        return extract_findings(await self.run_techniques(endpoints, session_manager, session_pool, evidence))

    def _result(self, technique_id: str, technique: str, status: str, detail: str, finding: Finding | None = None) -> TestCaseResult:
        # `test_id` is `technique_id`'s own top-level id (e.g. "TC-142.1"
        # -> "TC-142"), NOT a single shared "TC-140" for all five --
        # these five techniques are five genuinely distinct vulnerability
        # classes (bypass, tampering, missing rate limiting, replay, weak
        # code), not sibling sub-techniques confirming the SAME root
        # cause the way e.g. tenant_tests.py's TC-131.1/.2 do. Grouping
        # them under one top-level id fed straight into `results.py`'s
        # `_merge_root_cause_duplicates()` -- which deliberately
        # consolidates same-top-level-id findings on the same endpoint
        # -- and silently dropped a real, independent finding (confirmed
        # live: TC-142.1's rate-limiting FAIL and TC-143.1's replay FAIL,
        # both on POST .../login, collapsed into one reported finding).
        test_id = technique_id.split(".")[0]
        return self._make_result(
            test_id=test_id, technique_id=technique_id, technique=technique, vuln_type="MFA/TOTP Weakness",
            status=status, detail=detail, role=self.config.test_role, finding=finding,
        )

    def _ready(self) -> str | None:
        """Shared precondition every technique needs -- returns a SKIP
        reason string, or `None` if the module has what it needs to run
        at all. Centralized so five techniques don't repeat the same
        four-field null-check."""
        if not (self.config.login_url and self.config.test_username and self.config.test_password):
            return "no login_url/test_username/test_password configured for this role"
        if not self.config.totp_secret:
            return "no TOTP secret configured for this role -- this target either has no MFA step, or the operator hasn't provided the secret (Settings -> Credentials -> TOTP secret)"
        return None

    async def run_techniques(self, endpoints, session_manager, session_pool: "SessionPool", evidence=None) -> list[TestCaseResult]:
        skip_reason = self._ready()
        if skip_reason:
            return [
                self._result(tid, technique, SKIPPED, skip_reason)
                for tid, technique in (
                    ("TC-140.1", "Pre-MFA session/endpoint access"),
                    ("TC-141.1", "OTP verification response manipulation"),
                    ("TC-142.1", "OTP brute-force / missing rate limiting"),
                    ("TC-143.1", "OTP replay (reuse of an already-consumed code)"),
                    ("TC-144.1", "Static/weak OTP acceptance (000000)"),
                )
            ]
        results: list[TestCaseResult] = []
        results.append(await self._safe_result(
            self._technique_pre_mfa_access(endpoints, session_pool),
            "TC-140", "TC-140.1", "Pre-MFA session/endpoint access", "MFA Bypass (Pre-MFA Session Privilege)", role=self.config.test_role,
        ))
        results.append(await self._safe_result(
            self._technique_response_manipulation(session_pool, evidence),
            "TC-141", "TC-141.1", "OTP verification response manipulation", "MFA Bypass (Client-Trusted Response)", role=self.config.test_role,
        ))
        results.append(await self._safe_result(
            self._technique_brute_force(session_pool),
            "TC-142", "TC-142.1", "OTP brute-force / missing rate limiting", "Missing MFA Rate Limiting", role=self.config.test_role,
        ))
        results.append(await self._safe_result(
            self._technique_otp_replay(session_pool),
            "TC-143", "TC-143.1", "OTP replay (reuse of an already-consumed code)", "MFA OTP Replay", role=self.config.test_role,
        ))
        results.append(await self._safe_result(
            self._technique_static_code(session_pool),
            "TC-144", "TC-144.1", "Static/weak OTP acceptance (000000)", "MFA Weak/Static Code Accepted", role=self.config.test_role,
        ))
        return results

    # --- TC-140.1 Pre-MFA session/endpoint access ------------------------

    async def _technique_pre_mfa_access(self, endpoints: list[Endpoint], session_pool: "SessionPool") -> TestCaseResult:
        tid, technique = "TC-140.1", "Pre-MFA session/endpoint access"
        vuln_type = "MFA Bypass (Pre-MFA Session Privilege)"
        protected = next((e for e in endpoints if e.auth_required), None)
        if protected is None:
            return self._result(tid, technique, SKIPPED, "no crawler-discovered, auth-required endpoint to probe (run the crawler first)")

        context = await session_pool.new_anonymous_context()
        try:
            page = await context.new_page()
            try:
                await _submit_primary_credentials(page, self.config.login_url, self.config.test_username, self.config.test_password)
            finally:
                await page.close()
            # Whatever cookies/headers the primary-credentials step
            # itself set (a "tmpToken"/pending-2FA cookie, or -- the
            # vulnerable case -- a fully privileged session) are already
            # on `context` at this point; this probe uses them exactly
            # as issued, without ever completing the OTP step.
            resp = await context.request.get(protected.url, max_redirects=0)
            body = await resp.text()
        finally:
            await context.close()

        if resp.status >= 400 or len(body) < 20:
            return self._result(tid, technique, PASS, f"'{protected.url}' returned HTTP {resp.status} using only the pre-MFA session -- MFA step is enforced before this endpoint grants access")

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=9.1,
            endpoint=protected, user_role=self.config.test_role or "unauthenticated",
            request_raw=f"GET {protected.url}\n[cookies/headers from the pre-MFA credentials-accepted response only -- OTP step never completed]",
            response_raw=f"HTTP {resp.status}, {len(body)} bytes",
            description=(
                f"Submitting only the primary username/password for '{self.config.test_username}' (2FA step never "
                f"completed) already issued a session that could reach '{protected.url}', a crawler-discovered "
                "authenticated endpoint. This matches the most commonly reported real-world MFA-bypass pattern: "
                "the server hands out a fully privileged session at the FIRST factor instead of a reduced-privilege "
                "token that only becomes valid after the OTP is verified."
            ),
            recommendation=(
                "Issue only a short-lived, explicitly-scoped 'pending 2FA' token after the primary credentials step "
                "-- one that is rejected by every authenticated endpoint until the OTP is independently verified and "
                "a separate, fully privileged session is issued."
            ),
        )
        return self._result(tid, technique, FAIL, finding.description, finding=finding)

    # --- TC-141.1 OTP verification response manipulation -----------------

    async def _technique_response_manipulation(self, session_pool: "SessionPool", evidence) -> TestCaseResult:
        tid, technique = "TC-141.1", "OTP verification response manipulation"
        vuln_type = "MFA Bypass (Client-Trusted Response)"
        context = await session_pool.new_anonymous_context()
        try:
            page = await context.new_page()
            try:
                await _submit_primary_credentials(page, self.config.login_url, self.config.test_username, self.config.test_password)
                otp_sel = await _find_selector(page, _TOTP_SELECTORS)
                if otp_sel is None:
                    return self._result(tid, technique, SKIPPED, "no OTP field appeared after primary credentials -- this target's MFA step isn't on the same page STOF can locate")

                async def _flip_response(route):
                    response = await route.fetch()
                    try:
                        body = await response.json()
                    except Exception:
                        await route.continue_()
                        return
                    changed = False
                    if isinstance(body, dict):
                        for key in _TRUST_BOOLEAN_KEYS:
                            if body.get(key) is False:
                                body[key] = True
                                changed = True
                    if not changed:
                        await route.continue_()
                        return
                    import json as _json
                    await route.fulfill(response=response, status=200, body=_json.dumps(body))

                await page.route("**/*", _flip_response)
                try:
                    # A deliberately WRONG code -- if the real response
                    # ever says false and this technique flips it to
                    # true and the app still proceeds, that's the finding
                    # regardless of what the server's real answer was.
                    await page.fill(otp_sel, "000000")
                    submit_sel = await _find_selector(page, _SUBMIT_SELECTORS)
                    if submit_sel:
                        await page.click(submit_sel)
                    await page.wait_for_timeout(2000)
                finally:
                    await page.unroute("**/*", _flip_response)
            finally:
                current_url = page.url
                await page.close()
        finally:
            await context.close()

        if current_url.rstrip("/") == self.config.login_url.rstrip("/") or "totp" in current_url.lower() or "2fa" in current_url.lower():
            return self._result(tid, technique, PASS, "tampering the OTP-verification response (false->true) did not move the client past the MFA step -- the app doesn't trust a client-visible response field alone")

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=9.4,
            endpoint=Endpoint(url=self.config.login_url, method="POST", endpoint_type="api", auth_required=False),
            user_role=self.config.test_role or "unauthenticated",
            request_raw=f"POST {self.config.login_url} [OTP field submitted: 000000 (intentionally wrong)]",
            response_raw=f"intercepted OTP-verification response, flipped a false boolean field ({', '.join(_TRUST_BOOLEAN_KEYS)}) to true -- client navigated to {current_url}",
            description=(
                "Submitting a deliberately incorrect OTP code, then intercepting and flipping the verification "
                f"response's own success/valid/verified boolean from false to true, moved the client on to "
                f"'{current_url}' -- the SAME technique behind the majority of publicly disclosed MFA-bypass "
                "bug-bounty reports (client trusts a response field instead of a server-issued, cryptographically "
                "verified session)."
            ),
            recommendation=(
                "Never gate access on a client-visible boolean alone. Issue the real, authenticated session cookie/"
                "token ONLY in the server's OTP-verification response itself, and have every subsequent request "
                "re-check that session server-side -- an attacker who can intercept traffic should gain nothing "
                "from editing a response field."
            ),
        )
        return self._result(tid, technique, FAIL, finding.description, finding=finding)

    # --- TC-142.1 OTP brute-force / missing rate limiting -----------------

    async def _submit_otp_and_capture_post_response(self, page: "Page", code: str) -> tuple[int | None, str]:
        """One brute-force attempt's full body, extracted from
        `_technique_brute_force`'s loop so that method stays orchestration-
        only (same "extract a helper before a method drifts past this
        project's own complexity gate" convention every other module
        family in this codebase already follows). Captures the OTP-
        verification POST's real status/body via a `page.on("response",
        ...)` listener rather than `expect_response()`'s context-manager
        form -- functionally equivalent, but a plain callback is what
        every existing test fixture in this codebase already knows how
        to mock (see `test_mfa_tests.py`)."""
        captured: dict[str, object] = {}

        async def _capture(response) -> None:
            if response.request.method == "POST":
                captured["status"] = response.status
                try:
                    captured["body"] = await response.text()
                except Exception:
                    captured["body"] = ""

        await _submit_primary_credentials(page, self.config.login_url, self.config.test_username, self.config.test_password)
        otp_sel = await _find_selector(page, _TOTP_SELECTORS, timeout_ms=2000)
        if otp_sel is None:
            return None, ""
        page.on("response", _capture)
        try:
            await page.fill(otp_sel, code)
            submit_sel = await _find_selector(page, _SUBMIT_SELECTORS)
            if submit_sel:
                await page.click(submit_sel)
            await page.wait_for_timeout(1500)
        finally:
            page.remove_listener("response", _capture)
        return captured.get("status"), captured.get("body", "")

    async def _technique_brute_force(self, session_pool: "SessionPool") -> TestCaseResult:
        tid, technique = "TC-142.1", "OTP brute-force / missing rate limiting"
        vuln_type = "Missing MFA Rate Limiting"
        context = await session_pool.new_anonymous_context()
        statuses: list[int] = []
        bodies: list[str] = []
        try:
            page = await context.new_page()
            try:
                await _submit_primary_credentials(page, self.config.login_url, self.config.test_username, self.config.test_password)
                otp_sel = await _find_selector(page, _TOTP_SELECTORS)
            finally:
                await page.close()
            if otp_sel is None:
                return self._result(tid, technique, SKIPPED, "no OTP field appeared after primary credentials")

            for i in range(_BRUTE_FORCE_ATTEMPT_COUNT):
                guess = f"{(100000 + i * 111111) % 1000000:06d}"  # spread, not sequential -- avoids tripping a naive "same code twice" guard instead of real rate limiting
                p = await context.new_page()
                try:
                    status, body = await self._submit_otp_and_capture_post_response(p, guess)
                    if status is None:
                        break
                    statuses.append(status)
                    bodies.append(body[:200])
                except Exception as exc:
                    _log.warning(f"brute-force probe attempt {i} failed: {exc}")
                finally:
                    await p.close()
        finally:
            await context.close()

        if not statuses:
            return self._result(tid, technique, SKIPPED, "could not complete any OTP-submission attempts -- see log for details")

        throttled_seen = any(s in _RATE_LIMIT_STATUS_HINTS for s in statuses) or any(
            any(hint in b.lower() for hint in _RATE_LIMIT_BODY_HINTS) for b in bodies
        )
        if throttled_seen:
            return self._result(tid, technique, PASS, f"a rate-limit/lockout signal appeared within {len(statuses)} invalid OTP attempts")

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
            endpoint=Endpoint(url=self.config.login_url, method="POST", endpoint_type="api", auth_required=False),
            user_role=self.config.test_role or "unauthenticated",
            request_raw=f"POST {self.config.login_url} x{len(statuses)} [invalid OTP each time]",
            response_raw=f"statuses: {statuses}",
            description=(
                f"{len(statuses)} consecutive invalid OTP submissions for '{self.config.test_username}' all "
                f"received a normal 'invalid code' response (statuses: {statuses}) with no 429, lockout, or "
                "throttling signal. A real 6-digit TOTP code has only 1,000,000 possible values and a 30-second "
                "validity window -- without rate limiting, brute-forcing it is a bounded, automatable attack."
            ),
            recommendation=(
                "Rate-limit OTP verification attempts per account (not only per IP -- a distributed brute-force "
                "trivially evades IP-based limits): lock or delay the account after a small number of consecutive "
                "invalid codes, and log/alert on the pattern."
            ),
        )
        return self._result(tid, technique, FAIL, finding.description, finding=finding)

    # --- TC-143.1 OTP replay ----------------------------------------------

    async def _attempt_otp_login(self, session_pool: "SessionPool", code: str) -> tuple[bool, str] | None:
        """One full login-with-this-OTP-code attempt in a fresh,
        unauthenticated context -- `(succeeded, landed_url)`, or `None`
        if no OTP field ever appeared (the caller SKIPs in that case).
        Shared by `_technique_otp_replay`'s two (at most) attempts."""
        context = await session_pool.new_anonymous_context()
        try:
            page = await context.new_page()
            try:
                await _submit_primary_credentials(page, self.config.login_url, self.config.test_username, self.config.test_password)
                otp_sel = await _find_selector(page, _TOTP_SELECTORS)
                if otp_sel is None:
                    return None
                await page.fill(otp_sel, code)
                submit_sel = await _find_selector(page, _SUBMIT_SELECTORS)
                if submit_sel:
                    await page.click(submit_sel)
                await page.wait_for_timeout(1500)
                landed = page.url
                succeeded = landed.rstrip("/") != self.config.login_url.rstrip("/") and "totp" not in landed.lower() and "2fa" not in landed.lower()
                return succeeded, landed
            finally:
                await page.close()
        finally:
            await context.close()

    async def _technique_otp_replay(self, session_pool: "SessionPool") -> TestCaseResult:
        tid, technique = "TC-143.1", "OTP replay (reuse of an already-consumed code)"
        vuln_type = "MFA OTP Replay"
        code = pyotp.TOTP(self.config.totp_secret).now()

        first = await self._attempt_otp_login(session_pool, code)
        if first is None:
            return self._result(tid, technique, SKIPPED, "no OTP field appeared after primary credentials")
        first_success, _ = first
        if not first_success:
            return self._result(tid, technique, SKIPPED, "the freshly generated TOTP code was not accepted on first use -- cannot test replay without a known-valid, already-consumed code")

        second = await self._attempt_otp_login(session_pool, code)
        second_success, second_url = second if second is not None else (False, "")
        if not second_success:
            return self._result(tid, technique, PASS, "the same valid OTP code was correctly rejected on its second use")

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="High", cvss_score=7.5,
            endpoint=Endpoint(url=self.config.login_url, method="POST", endpoint_type="api", auth_required=False),
            user_role=self.config.test_role or "unauthenticated",
            request_raw=f"POST {self.config.login_url} [same TOTP code submitted twice, in two separate login attempts]",
            response_raw=f"second attempt landed on {second_url}",
            description=(
                f"The same valid TOTP code for '{self.config.test_username}' was accepted a second time in a "
                "separate login attempt within its own validity window. TOTP codes must be single-use: an attacker "
                "who observes a code once (network capture, shoulder-surfing, a compromised log) can reuse it for "
                "the rest of its ~30-second window."
            ),
            recommendation="Invalidate a TOTP code server-side immediately after its first successful use, for the remainder of its time-step window.",
        )
        return self._result(tid, technique, FAIL, finding.description, finding=finding)

    # --- TC-144.1 Static/weak code acceptance ------------------------------

    async def _technique_static_code(self, session_pool: "SessionPool") -> TestCaseResult:
        tid, technique = "TC-144.1", "Static/weak OTP acceptance (000000)"
        vuln_type = "MFA Weak/Static Code Accepted"
        real_code = pyotp.TOTP(self.config.totp_secret).now()
        weak_candidates = [c for c in ("000000", "123456", "111111") if c != real_code]

        context = await session_pool.new_anonymous_context()
        try:
            page = await context.new_page()
            try:
                await _submit_primary_credentials(page, self.config.login_url, self.config.test_username, self.config.test_password)
                otp_sel = await _find_selector(page, _TOTP_SELECTORS)
                if otp_sel is None:
                    return self._result(tid, technique, SKIPPED, "no OTP field appeared after primary credentials")
                accepted_code = None
                for candidate in weak_candidates:
                    await page.fill(otp_sel, candidate)
                    submit_sel = await _find_selector(page, _SUBMIT_SELECTORS)
                    if submit_sel:
                        await page.click(submit_sel)
                    await page.wait_for_timeout(1200)
                    landed = page.url
                    if landed.rstrip("/") != self.config.login_url.rstrip("/") and "totp" not in landed.lower() and "2fa" not in landed.lower():
                        accepted_code = candidate
                        break
                    # Reset back to the login page for the next candidate.
                    await page.goto(self.config.login_url, wait_until="domcontentloaded")
                    otp_sel = await _find_selector(page, _TOTP_SELECTORS, timeout_ms=1500)
                    if otp_sel is None:
                        break
            finally:
                await page.close()
        finally:
            await context.close()

        if accepted_code is None:
            return self._result(tid, technique, PASS, f"none of {weak_candidates} were accepted as a valid OTP")

        finding = Finding(
            module_id=self.module_id, vuln_type=vuln_type, severity="Critical", cvss_score=9.8,
            endpoint=Endpoint(url=self.config.login_url, method="POST", endpoint_type="api", auth_required=False),
            user_role=self.config.test_role or "unauthenticated",
            request_raw=f"POST {self.config.login_url} [OTP field: {accepted_code}]",
            response_raw="client navigated past the MFA step",
            description=(
                f"A common/static code ('{accepted_code}') -- not the real, freshly generated TOTP value -- was "
                f"accepted as valid MFA for '{self.config.test_username}'. This indicates the server isn't "
                "actually validating the submitted code against the account's real TOTP secret at all."
            ),
            recommendation="Verify every submitted OTP against the account's real, server-side TOTP secret using standard RFC 6238 validation -- never accept a hardcoded/bypass value in any environment reachable by this scan.",
        )
        return self._result(tid, technique, FAIL, finding.description, finding=finding)
