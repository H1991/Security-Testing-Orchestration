"""Unit tests for Layer 5 — stof.session.token_refresh."""
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthExpiredError
from stof.session.models import Session
from stof.session.token_refresh import DEFAULT_EXPIRY_BUFFER, needs_refresh, try_refresh


def _session(**overrides) -> Session:
    defaults = dict(user_id="u", role="admin", auth_type="jwt")
    defaults.update(overrides)
    return Session(**defaults)


# ---------------------------------------------------------------------------
# needs_refresh — happy path
# ---------------------------------------------------------------------------


def test_needs_refresh_false_for_valid_session_with_no_expiry():
    assert needs_refresh(_session()) is False


def test_needs_refresh_false_when_expiry_is_far_in_the_future():
    session = _session(expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
    assert needs_refresh(session) is False


def test_needs_refresh_true_when_already_invalid():
    session = _session(is_valid=False)
    assert needs_refresh(session) is True


def test_needs_refresh_true_when_expired():
    session = _session(expires_at=datetime.now(timezone.utc) - timedelta(minutes=1))
    assert needs_refresh(session) is True


# ---------------------------------------------------------------------------
# needs_refresh — buffer boundary (input validation)
# ---------------------------------------------------------------------------


def test_needs_refresh_true_when_expiry_is_within_the_buffer():
    session = _session(expires_at=datetime.now(timezone.utc) + timedelta(seconds=10))
    assert needs_refresh(session, buffer=DEFAULT_EXPIRY_BUFFER) is True


def test_needs_refresh_respects_custom_buffer():
    session = _session(expires_at=datetime.now(timezone.utc) + timedelta(seconds=10))
    assert needs_refresh(session, buffer=timedelta(seconds=1)) is False


# ---------------------------------------------------------------------------
# try_refresh
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_try_refresh_returns_refreshed_session_on_success():
    session = _session()
    refreshed = _session(headers={"Authorization": "Bearer new"})
    page = AsyncMock()
    provider = AsyncMock()
    provider.refresh = AsyncMock(return_value=refreshed)

    result = await try_refresh(provider, session, page)

    assert result is refreshed
    provider.refresh.assert_awaited_once_with(session, page)


@pytest.mark.asyncio
async def test_try_refresh_returns_none_when_provider_raises_auth_expired():
    session = _session()
    provider = AsyncMock()
    provider.refresh = AsyncMock(side_effect=AuthExpiredError("no refresh_url"))

    result = await try_refresh(provider, session, page=AsyncMock())

    assert result is None
