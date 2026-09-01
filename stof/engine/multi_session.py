"""Layer 3B — concurrent multi-user session management.

Manages a pool of browser contexts, one per user role, launched from a
single shared browser so multiple roles can be exercised concurrently
within a scan. Contexts are reused across replay calls rather than
recreated per action.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urlparse

from stof.core.logger import get_logger

if TYPE_CHECKING:
    from playwright.async_api import Browser, BrowserContext, Playwright

    from stof.config import BrowserConfig

_log = get_logger("engine.multi_session")


class SessionLike(Protocol):
    """Structural shape this module needs from a session.

    Layer 5's `session.session_manager.Session` dataclass will satisfy
    this automatically once built — no import from `stof.session` is
    needed here, per the loose-coupling rule (data contracts, not
    sibling internals).
    """

    role: str
    cookies: dict[str, str]
    headers: dict[str, str]


def _to_playwright_cookies(cookies: dict[str, str], url: str) -> list[dict[str, Any]]:
    domain = urlparse(url).hostname or ""
    return [{"name": name, "value": value, "domain": domain, "path": "/"} for name, value in cookies.items()]


class SessionPool:
    def __init__(self, browser: "Browser", ignore_https_errors: bool = False) -> None:
        self._browser = browser
        # Off by default -- silently trusting bad certs isn't something
        # a security testing tool should do out of the box. Turn it on
        # explicitly for targets known to have an expired/self-signed
        # cert (common on intentionally-vulnerable practice targets).
        self._ignore_https_errors = ignore_https_errors
        self._contexts: dict[str, "BrowserContext"] = {}
        self._lock = asyncio.Lock()

    @classmethod
    async def launch(
        cls,
        playwright: "Playwright",
        browser_config: "BrowserConfig",
        ignore_https_errors: bool = False,
    ) -> "SessionPool":
        """Launch a Chromium browser per Layer 1's `Config.browser`."""
        browser = await playwright.chromium.launch(
            headless=browser_config.headless,
            slow_mo=browser_config.slowmo_ms or None,
            proxy={"server": browser_config.proxy} if browser_config.proxy else None,
        )
        return cls(browser, ignore_https_errors=ignore_https_errors)

    async def get_context(self, role: str) -> "BrowserContext":
        async with self._lock:
            context = self._contexts.get(role)
            if context is None:
                context = await self._browser.new_context(ignore_https_errors=self._ignore_https_errors)
                self._contexts[role] = context
                _log.info(f"created browser context for role '{role}'")
            return context

    async def apply_session(self, session: SessionLike, target_url: str) -> "BrowserContext":
        """Get (or create) this role's context and sync the session's
        cookies/headers onto it."""
        context = await self.get_context(session.role)
        if session.cookies:
            await context.add_cookies(_to_playwright_cookies(session.cookies, target_url))
        if session.headers:
            await context.set_extra_http_headers(session.headers)
        return context

    async def new_anonymous_context(self) -> "BrowserContext":
        """A fresh, uncached, unauthenticated context -- for probes that
        need to prove something about *absence* of a session (e.g. "is
        this endpoint actually protected against an anonymous caller?"),
        which `get_context(role)`'s role-keyed cache has no slot for.
        Caller owns the returned context's lifecycle and must close it;
        unlike role contexts, it's never tracked in `self._contexts` so
        `close_all()`/`shutdown()` won't also close it out from under
        an in-flight caller."""
        return await self._browser.new_context(ignore_https_errors=self._ignore_https_errors)

    async def close(self, role: str) -> None:
        async with self._lock:
            context = self._contexts.pop(role, None)
        if context is not None:
            await context.close()

    async def close_all(self) -> None:
        async with self._lock:
            contexts = list(self._contexts.values())
            self._contexts.clear()
        for context in contexts:
            await context.close()

    async def shutdown(self) -> None:
        """Close every context and the underlying browser."""
        await self.close_all()
        await self._browser.close()
