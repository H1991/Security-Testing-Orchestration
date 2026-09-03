"""Unit tests for Layer 4 — stof.auth.assisted_login."""
from unittest.mock import AsyncMock

import pytest

from stof.auth.assisted_login import AssistedLoginProvider
from stof.auth.base import AuthExpiredError, AuthFailedError
from stof.config.schema import UserConfig
from stof.session.models import Session

LOGIN_URL = "https://pentest.demo-aws.mymovein.com/"


def _user() -> UserConfig:
    return UserConfig(
        id="admin-01",
        role="admin",
        username="zain.ahmed@nusummit.com",
        password="s3cr3t",
        auth_type="form_login",
    )


def _page(url: str, cookies: list[dict] | None = None) -> AsyncMock:
    """Same shape as `test_form_login.py`'s own `_page()` -- this
    provider reuses `wait_for_login_success()`/`extract_cookies()` from
    that module unchanged, so the same fixture shape applies."""
    page = AsyncMock()
    page.url = url
    page.context.cookies = AsyncMock(return_value=cookies or [])
    return page


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authenticate_confirms_via_url_change_and_captures_cookies():
    """No credentials are ever filled/submitted here -- the human
    already did that. This only confirms success (navigated away from
    the login URL) and captures whatever cookies the operator's real,
    already-authenticated browser now has."""
    provider = AssistedLoginProvider(login_url=LOGIN_URL)
    page = _page("https://pentest.demo-aws.mymovein.com/dashboard", cookies=[{"name": "session_id", "value": "real-human-session"}])

    session = await provider.authenticate(_user(), page)

    assert session.auth_type == "assisted_manual"
    assert session.cookies == {"session_id": "real-human-session"}
    assert session.role == "admin"
    assert session.expires_at is not None


@pytest.mark.asyncio
async def test_authenticate_confirms_via_success_selector():
    provider = AssistedLoginProvider(login_url=LOGIN_URL, success_selector="text=Welcome back")
    page = _page(LOGIN_URL, cookies=[{"name": "auth", "value": "xyz"}])
    page.wait_for_selector = AsyncMock(return_value=None)

    session = await provider.authenticate(_user(), page)

    assert session.cookies == {"auth": "xyz"}
    page.wait_for_selector.assert_awaited()


@pytest.mark.asyncio
async def test_authenticate_never_navigates_or_fills_fields():
    """The whole point of assisted login: STOF must never touch the
    page's own navigation/form state -- the human already established
    it, and re-navigating could throw that away."""
    provider = AssistedLoginProvider(login_url=LOGIN_URL)
    page = _page("https://pentest.demo-aws.mymovein.com/dashboard")

    await provider.authenticate(_user(), page)

    page.goto.assert_not_awaited()
    page.fill.assert_not_awaited()
    page.click.assert_not_awaited()


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authenticate_raises_when_still_on_login_page():
    """The human hasn't actually completed login (or the challenge)
    yet -- must fail clearly, never silently proceed as if it succeeded."""
    provider = AssistedLoginProvider(login_url=LOGIN_URL, timeout_ms=50)
    page = _page(LOGIN_URL)  # still on the login URL
    page.wait_for_url = AsyncMock(side_effect=TimeoutError("timed out"))

    with pytest.raises(AuthFailedError, match="login could not be confirmed"):
        await provider.authenticate(_user(), page)


@pytest.mark.asyncio
async def test_refresh_always_raises_auth_expired():
    """No automated refresh path exists -- clearing a bot-challenge
    again needs a human, which SessionManager cannot do on its own."""
    provider = AssistedLoginProvider(login_url=LOGIN_URL)
    session = Session(user_id="admin-01", role="admin", auth_type="assisted_manual", cookies={"a": "b"})

    with pytest.raises(AuthExpiredError, match="cannot be refreshed automatically"):
        await provider.refresh(session, _page(LOGIN_URL))


# ---------------------------------------------------------------------------
# is_authenticated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_is_authenticated_false_when_session_marked_invalid():
    provider = AssistedLoginProvider(login_url=LOGIN_URL)
    session = Session(user_id="admin-01", role="admin", auth_type="assisted_manual", cookies={"a": "b"}, is_valid=False)

    assert await provider.is_authenticated(session, _page(LOGIN_URL)) is False


@pytest.mark.asyncio
async def test_is_authenticated_true_when_cookies_still_match():
    provider = AssistedLoginProvider(login_url=LOGIN_URL)
    session = Session(user_id="admin-01", role="admin", auth_type="assisted_manual", cookies={"session_id": "real-human-session"})
    page = _page(LOGIN_URL, cookies=[{"name": "session_id", "value": "real-human-session"}])

    assert await provider.is_authenticated(session, page) is True
