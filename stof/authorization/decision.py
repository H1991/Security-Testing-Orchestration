"""Shared response -> authorization-decision classifier.

Every authorization-testing technique across `idor_tests.py` and
`jwt_tests.py` currently hand-rolls its own "is this a hit" check --
almost always `resp.status == 200 and len(body) >= min_content_length`.
That misses the common "soft 403" pattern (a 200 response whose body
is an access-denied page) and treats every other status as a uniform
non-hit. Centralising the check here means every technique gets the
same, better signal, and future techniques don't re-derive it.
"""
from __future__ import annotations

from enum import Enum

_DENIAL_MARKERS = (
    "access denied", "access is denied", "forbidden", "unauthorized",
    "not authorized", "permission denied", "you do not have permission",
    "insufficient privileges", "login required", "please log in", "please sign in",
)

_LOGIN_PATH_MARKERS = ("login", "signin", "sign-in", "auth")


class AuthorizationDecision(str, Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    REDIRECTED = "REDIRECTED"
    CHALLENGED = "CHALLENGED"
    UNKNOWN = "UNKNOWN"


def classify_response(
    status: int,
    body: str,
    *,
    redirect_location: str | None = None,
    min_content_length: int = 100,
) -> AuthorizationDecision:
    """Combine status, redirect target, and body content into one
    decision. Order matters: an explicit denial phrase in a 200-status
    body outranks the raw status code, since apps frequently return
    200 for a rendered "access denied" page instead of a real 401/403."""
    if status in (401, 403):
        return AuthorizationDecision.DENIED
    if status == 429:
        return AuthorizationDecision.CHALLENGED
    if status in (301, 302, 303, 307, 308):
        if redirect_location and any(marker in redirect_location.lower() for marker in _LOGIN_PATH_MARKERS):
            return AuthorizationDecision.DENIED
        return AuthorizationDecision.REDIRECTED
    if 200 <= status < 300:
        lowered = body.lower()
        if any(marker in lowered for marker in _DENIAL_MARKERS):
            return AuthorizationDecision.DENIED
        if len(body) >= min_content_length:
            return AuthorizationDecision.ALLOWED
        return AuthorizationDecision.UNKNOWN
    return AuthorizationDecision.UNKNOWN
