"""Layer 4 — Assisted (human-in-the-loop) login provider.

For a target sitting behind a bot-challenge (Cloudflare's "Performing
security verification" interstitial, or equivalent) that STOF's own
automated Playwright browser can never pass on its own -- confirmed
live against a real target this session, whose Verify Login screenshot
showed the challenge page itself, never the application. Every
automated DAST tool hits this same wall; OWASP ZAP's own documentation
is explicit that defeating a WAF/bot-challenge isn't the scanner's job.

Unlike `FormLoginProvider`, this provider does NOT fill in credentials
or click a submit button -- a human operator has already done that
manually, in their own real browser, before this is ever called. Its
only jobs are: (1) confirm the page it's handed really is past the
login flow (never trust "the operator said so" alone -- reuses
`wait_for_login_success()`'s exact success-selector/URL-change check
`FormLoginProvider` already uses), and (2) capture the resulting
cookies into a `Session`, via the same `extract_cookies()` shape.

Critically, the `Session` this returns matters far less than it does
for `FormLoginProvider`: a captured cookie alone does not survive a
handoff to a *different* browser/process/IP (Cloudflare's clearance is
cryptographically bound to the exact fingerprint that earned it,
confirmed via research this session -- this is why the assisted-login
design does NOT copy cookies into STOF's own headless browser). The
real mechanism that makes this work is `SessionPool.
attach_external_context()` (`stof/engine/multi_session.py`): the SAME
CDP-attached, human-cleared browser context keeps handling that role's
traffic for the rest of the scan. This provider's `Session` exists for
logging/reporting continuity with every other auth_type, not because
its cookies get reused elsewhere.

There is no automated refresh path: if the operator's browser or
network connection drops mid-scan, that is a hard failure surfaced
clearly (see `refresh()` below), never a silent automated retry that
would just hit the same bot-challenge wall again.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from stof.core.logger import get_logger
from stof.session.models import Session

from .base import AuthExpiredError, AuthProvider
from .form_login import extract_cookies, wait_for_login_success

if TYPE_CHECKING:
    from playwright.async_api import Page

    from stof.config.schema import UserConfig

_log = get_logger("auth.assisted_login")

# A human needs real time to notice the browser, solve whatever
# challenge is presented, and complete the login form -- this is
# minutes, not FormLoginProvider's fast programmatic ~10s default.
DEFAULT_TIMEOUT_MS = 5 * 60 * 1000

# Generous on purpose: this session is never automatically refreshed
# (see `refresh()`), so its assumed lifetime just needs to comfortably
# outlast one scan run, not model the target's real session timeout.
DEFAULT_SESSION_LIFETIME = timedelta(hours=6)


class AssistedLoginProvider(AuthProvider):
    def __init__(
        self,
        login_url: str,
        success_selector: str | list[str] | None = None,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        session_lifetime: timedelta = DEFAULT_SESSION_LIFETIME,
    ) -> None:
        self._login_url = login_url
        self._success_selector = success_selector
        self._timeout_ms = timeout_ms
        self._session_lifetime = session_lifetime

    async def authenticate(self, user: "UserConfig", page: "Page") -> Session:
        # Deliberately does NOT page.goto(self._login_url) or touch any
        # form field -- the human operator already drove this page
        # (including clearing whatever challenge was presented) before
        # `main.py` ever calls this. Re-navigating here would risk
        # throwing away the exact state the human just established.
        await wait_for_login_success(page, self._login_url, self._success_selector, self._timeout_ms, f"assisted login (role={user.role})")
        cookies = await extract_cookies(page)
        expires_at = datetime.now(timezone.utc) + self._session_lifetime
        session = Session(user_id=user.id, role=user.role, auth_type="assisted_manual", cookies=cookies, expires_at=expires_at)
        _log.info(f"confirmed assisted login for role '{user.role}' (user_id={user.id}), expires_at={expires_at}")
        return session

    async def refresh(self, session: Session, page: "Page") -> Session:
        # No automated refresh: re-clearing a bot-challenge needs a
        # human again, which SessionManager cannot do on its own. The
        # caller is expected to surface this as a hard scan failure
        # ("assisted login expired mid-scan -- re-run the assisted
        # login step and start a new scan"), not attempt anything
        # automated that would just hit the same wall.
        raise AuthExpiredError(
            f"assisted_manual session {session.session_id} cannot be refreshed automatically; "
            "a human must clear the challenge again"
        )

    async def is_authenticated(self, session: Session, page: "Page") -> bool:
        if not session.is_valid:
            return False
        current_cookies = await extract_cookies(page)
        return all(current_cookies.get(name) == value for name, value in session.cookies.items())
