"""Layer 5 — Session Manager.

Maintains one live Session per user role for the duration of a scan.
Vulnerability modules (Layer 9) call `get_session(role)` only -- they
never drive authentication themselves.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from stof.core.logger import get_logger

from .models import Session
from .session_store import SessionStore
from .token_refresh import needs_refresh, try_refresh

if TYPE_CHECKING:
    from playwright.async_api import Page

    from stof.auth.base import AuthProvider
    from stof.config.schema import UserConfig

_log = get_logger("session.session_manager")


class SessionManager:
    """`users` maps role -> UserConfig (Layer 1). `providers` maps
    auth_type -> AuthProvider (Layer 4) -- keyed by auth_type rather
    than role because Phase 1's `Config` (Layer 1) has one shared
    `target`/`login_url` for the whole scan, so every `form_login` role
    genuinely shares one `FormLoginProvider`, and every `jwt` role
    shares one `JWTAuthProvider`; this also matches `stof.auth`'s own
    `AUTH_PROVIDERS` registry, which is keyed by auth_type.
    """

    def __init__(
        self,
        users: dict[str, "UserConfig"],
        providers: dict[str, "AuthProvider"],
        store: SessionStore | None = None,
    ) -> None:
        self._users = users
        self._providers = providers
        self._store = store or SessionStore()
        self._sessions: dict[str, Session] = dict(self._store.load_all())
        self._locks: dict[str, asyncio.Lock] = {}

    def _lock_for(self, role: str) -> asyncio.Lock:
        lock = self._locks.get(role)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[role] = lock
        return lock

    async def get_session(self, role: str, page: "Page") -> Session:
        """Return a valid Session for `role`: the cached one if it's
        still fresh, a refreshed one if it wasn't, or a freshly
        authenticated one if refresh wasn't possible. This is the only
        auth entry point a vulnerability module should call -- it never
        manages its own auth."""
        async with self._lock_for(role):
            session = self._sessions.get(role)
            if session is not None and not needs_refresh(session):
                return session

            user = self._users.get(role)
            if user is None:
                raise KeyError(f"no configured user for role '{role}'")
            provider = self._providers.get(user.auth_type)
            if provider is None:
                raise KeyError(f"no auth provider registered for auth_type '{user.auth_type}'")

            if session is not None:
                refreshed = await try_refresh(provider, session, page)
                if refreshed is not None:
                    self._sessions[role] = refreshed
                    self._store.save(refreshed)
                    return refreshed

            new_session = await provider.authenticate(user, page)
            self._sessions[role] = new_session
            self._store.save(new_session)
            _log.info(f"authenticated fresh session for role '{role}'")
            return new_session

    def invalidate(self, role: str) -> None:
        """Mark a role's session invalid (e.g. after a vulnerability
        module confirms a logout/session-fixation finding), forcing
        re-authentication on the next get_session() call."""
        session = self._sessions.get(role)
        if session is not None:
            session.is_valid = False
            self._store.save(session)
