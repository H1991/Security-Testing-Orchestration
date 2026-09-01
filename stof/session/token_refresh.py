"""Layer 5 — refresh policy: decides when a session needs refreshing and
drives the provider's `refresh()` call.

The actual refresh mechanics (HTTP call, parsing the new token) live in
Layer 4's `auth.jwt_auth.JWTAuthProvider.refresh()`; this module only
adds the "is it time yet" policy and calls it uniformly for any
`AuthProvider` -- `form_login`'s `refresh()` always raises
`AuthExpiredError` (it has no refresh endpoint), which this module
treats the same as any other provider's refresh failure: "give up,
caller should authenticate() from scratch."
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from stof.core.logger import get_logger

from .models import Session

if TYPE_CHECKING:
    from playwright.async_api import Page

    from stof.auth.base import AuthProvider

_log = get_logger("session.token_refresh")

DEFAULT_EXPIRY_BUFFER = timedelta(seconds=30)


def needs_refresh(session: Session, buffer: timedelta = DEFAULT_EXPIRY_BUFFER) -> bool:
    """True if `session` is already invalid, or will expire within
    `buffer` of now (a small buffer avoids racing an in-flight request
    against the token expiring mid-use)."""
    if not session.is_valid:
        return True
    if session.expires_at is None:
        return False
    return datetime.now(timezone.utc) >= session.expires_at - buffer


async def try_refresh(provider: "AuthProvider", session: Session, page: "Page") -> Session | None:
    """Attempt to refresh `session` via `provider.refresh()`. Returns the
    refreshed Session, or None if refresh isn't possible -- the caller
    (session_manager) is expected to `authenticate()` from scratch."""
    # Deferred import: stof.auth.base imports Session from this
    # package (stof.session.models), so a module-level import here
    # would be circular -- by the time this function actually runs,
    # both packages are fully loaded and this is just a normal lookup.
    from stof.auth.base import AuthExpiredError

    try:
        refreshed = await provider.refresh(session, page)
    except AuthExpiredError as exc:
        _log.info(f"session {session.session_id} (role={session.role}) cannot be refreshed: {exc}")
        return None

    _log.info(f"refreshed session {refreshed.session_id} (role={refreshed.role})")
    return refreshed
