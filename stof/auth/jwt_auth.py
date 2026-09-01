"""Layer 4 — JWT / API Token auth provider (Phase 1).

Doesn't drive a login form at all: reads a bearer token and builds a
`Session` carrying it as a header. The header injection itself (actually
attaching `Authorization: Bearer <token>` to outgoing requests) happens
later, when Layer 3B's `SessionPool.apply_session()` calls
`context.set_extra_http_headers(session.headers)` -- this module's job
is only to produce that Session, and to track/refresh the token's
expiry.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from stof.core.logger import get_logger
from stof.session.models import Session

from .base import AuthExpiredError, AuthFailedError, AuthProvider

if TYPE_CHECKING:
    from playwright.async_api import Page

    from stof.config.schema import UserConfig

_log = get_logger("auth.jwt_auth")


def decode_jwt_exp(token: str) -> datetime | None:
    """Best-effort extraction of the `exp` claim from a JWT, without
    verifying its signature -- Layer 4 only needs to know expiry to
    decide when to refresh, not to validate trust (that's the target's
    job). Returns None if the token isn't a 3-part JWT or has no `exp`.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
    except Exception:
        return None
    exp = payload.get("exp")
    if exp is None:
        return None
    return datetime.fromtimestamp(exp, tz=timezone.utc)


# Real login endpoints disagree on both the request field name
# ("username" vs "email") and where the token lives in the response
# (flat "access_token"/"token", or nested under a wrapper key -- e.g.
# a real target confirmed live wraps it as {"authentication": {"token":
# ...}}). Neither list is target-specific: sending both request keys is
# harmless (a backend that doesn't recognize one just ignores it), and
# trying each response path in turn covers common shapes without
# requiring per-target config for the common case.
_TOKEN_RESPONSE_PATHS: tuple[tuple[str, ...], ...] = (
    ("access_token",),
    ("token",),
    ("authentication", "token"),
    ("data", "token"),
    ("data", "access_token"),
)


def _extract_token(body: dict, fallback: str) -> str:
    for path in _TOKEN_RESPONSE_PATHS:
        value: object = body
        for key in path:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                value = None
                break
        if isinstance(value, str) and value:
            return value
    return fallback


class JWTAuthProvider(AuthProvider):
    """`user.password` holds the token: Phase 1's `UserConfig` schema
    (Layer 1) has one credential slot, `password`, resolved via
    `{{env:VAR}}` same as any other user -- a `jwt`-auth_type user's
    `password` field is that token, not a literal password."""

    def __init__(self, token_url: str | None = None, refresh_url: str | None = None) -> None:
        self._token_url = token_url
        self._refresh_url = refresh_url

    async def authenticate(self, user: "UserConfig", page: "Page") -> Session:
        token = user.password
        if self._token_url is not None:
            response = await page.request.post(
                self._token_url,
                data={"username": user.username, "email": user.username, "password": token},
            )
            if response.status >= 400:
                raise AuthFailedError(
                    f"token endpoint {self._token_url} returned {response.status} for user '{user.id}'"
                )
            body = await response.json()
            token = _extract_token(body, fallback=token)

        expires_at = decode_jwt_exp(token)
        session = Session(
            user_id=user.id,
            role=user.role,
            auth_type="jwt",
            headers={"Authorization": f"Bearer {token}"},
            expires_at=expires_at,
        )
        _log.info(f"authenticated user '{user.id}' (role={user.role}) via jwt, expires_at={expires_at}")
        return session

    async def refresh(self, session: Session, page: "Page") -> Session:
        if self._refresh_url is None:
            raise AuthExpiredError(
                f"jwt session {session.session_id} expired and no refresh_url is configured"
            )

        response = await page.request.post(self._refresh_url, headers=session.headers)
        if response.status >= 400:
            raise AuthExpiredError(
                f"refresh_url {self._refresh_url} returned {response.status} "
                f"for session {session.session_id}"
            )

        body = await response.json()
        new_token = body.get("access_token") or body.get("token")
        if not new_token:
            raise AuthExpiredError(
                f"refresh_url response for session {session.session_id} had no "
                "access_token/token field"
            )

        session.headers["Authorization"] = f"Bearer {new_token}"
        session.expires_at = decode_jwt_exp(new_token)
        session.is_valid = True
        return session

    async def is_authenticated(self, session: Session, page: "Page") -> bool:
        if not session.is_valid:
            return False
        if session.expires_at is None:
            return True
        return datetime.now(timezone.utc) < session.expires_at
