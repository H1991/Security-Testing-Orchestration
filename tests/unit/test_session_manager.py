"""Unit tests for Layer 5 — stof.session.session_manager."""
import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthExpiredError
from stof.config.schema import UserConfig
from stof.session.models import Session
from stof.session.session_manager import SessionManager
from stof.session.session_store import SessionStore


def _user(role: str = "admin", auth_type: str = "form_login") -> UserConfig:
    return UserConfig(id=f"{role}-01", role=role, username=role, password="pw", auth_type=auth_type)


def _manager(tmp_path, users=None, providers=None) -> SessionManager:
    store = SessionStore(db_path=tmp_path / "stof.db")
    return SessionManager(users=users or {}, providers=providers or {}, store=store)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_session_authenticates_fresh_when_none_cached(tmp_path):
    user = _user("admin")
    new_session = Session(user_id="admin-01", role="admin", auth_type="form_login")
    provider = AsyncMock()
    provider.authenticate = AsyncMock(return_value=new_session)
    manager = _manager(tmp_path, users={"admin": user}, providers={"form_login": provider})

    result = await manager.get_session("admin", page=AsyncMock())

    assert result is new_session
    provider.authenticate.assert_awaited_once()
    provider.refresh.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_session_returns_cached_session_without_reauthenticating(tmp_path):
    user = _user("admin")
    provider = AsyncMock()
    manager = _manager(tmp_path, users={"admin": user}, providers={"form_login": provider})
    cached = Session(user_id="admin-01", role="admin", auth_type="form_login")
    manager._sessions["admin"] = cached

    result = await manager.get_session("admin", page=AsyncMock())

    assert result is cached
    provider.authenticate.assert_not_awaited()
    provider.refresh.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_session_refreshes_instead_of_reauthenticating_when_possible(tmp_path):
    user = _user("normal", auth_type="jwt")
    expiring = Session(
        user_id="normal-01",
        role="normal",
        auth_type="jwt",
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    refreshed = Session(user_id="normal-01", role="normal", auth_type="jwt")
    provider = AsyncMock()
    provider.refresh = AsyncMock(return_value=refreshed)
    manager = _manager(tmp_path, users={"normal": user}, providers={"jwt": provider})
    manager._sessions["normal"] = expiring

    result = await manager.get_session("normal", page=AsyncMock())

    assert result is refreshed
    provider.refresh.assert_awaited_once()
    provider.authenticate.assert_not_awaited()


# ---------------------------------------------------------------------------
# Failure cases -> fallback to fresh authentication
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_session_falls_back_to_authenticate_when_refresh_fails(tmp_path):
    user = _user("normal", auth_type="jwt")
    expired = Session(user_id="normal-01", role="normal", auth_type="jwt", is_valid=False)
    fresh = Session(user_id="normal-01", role="normal", auth_type="jwt")
    provider = AsyncMock()
    provider.refresh = AsyncMock(side_effect=AuthExpiredError("expired"))
    provider.authenticate = AsyncMock(return_value=fresh)
    manager = _manager(tmp_path, users={"normal": user}, providers={"jwt": provider})
    manager._sessions["normal"] = expired

    result = await manager.get_session("normal", page=AsyncMock())

    assert result is fresh
    provider.refresh.assert_awaited_once()
    provider.authenticate.assert_awaited_once()


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_session_unknown_role_raises_key_error(tmp_path):
    manager = _manager(tmp_path)

    with pytest.raises(KeyError, match="no configured user"):
        await manager.get_session("ghost", page=AsyncMock())


@pytest.mark.asyncio
async def test_get_session_no_provider_for_auth_type_raises_key_error(tmp_path):
    manager = _manager(tmp_path, users={"admin": _user("admin")}, providers={})

    with pytest.raises(KeyError, match="no auth provider"):
        await manager.get_session("admin", page=AsyncMock())


# ---------------------------------------------------------------------------
# invalidate()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invalidate_forces_reauthentication_on_next_get_session(tmp_path):
    user = _user("admin")
    cached = Session(user_id="admin-01", role="admin", auth_type="form_login")
    fresh = Session(user_id="admin-01", role="admin", auth_type="form_login")
    provider = AsyncMock()
    # form_login has no refresh endpoint -- refresh() always raises, same
    # as real FormLoginProvider behaviour -- forcing the fallback path.
    provider.refresh = AsyncMock(side_effect=AuthExpiredError("cannot be refreshed"))
    provider.authenticate = AsyncMock(return_value=fresh)
    manager = _manager(tmp_path, users={"admin": user}, providers={"form_login": provider})
    manager._sessions["admin"] = cached

    manager.invalidate("admin")
    result = await manager.get_session("admin", page=AsyncMock())

    assert cached.is_valid is False
    assert result is fresh
    provider.refresh.assert_awaited_once()
    provider.authenticate.assert_awaited_once()


def test_invalidate_unknown_role_does_not_raise(tmp_path):
    manager = _manager(tmp_path)

    manager.invalidate("ghost")  # must not raise


@pytest.mark.asyncio
async def test_seed_session_is_returned_by_get_session_without_calling_a_provider(tmp_path):
    """Assisted login (stof/auth/assisted_login.py): a session
    confirmed against a real, human-operated browser before the scan's
    normal flow starts must be usable exactly like a normally-
    authenticated one -- get_session() should hand it back directly,
    never touch a provider for it."""
    # UserConfig.auth_type stays "form_login" -- requires_assisted_login
    # is a TARGET-level switch, not a per-user auth_type value (see
    # stof/main.py's _build_login_provider docstring); "assisted_manual"
    # only ever appears as the resulting Session's own auth_type.
    user = _user("admin", auth_type="form_login")
    provider = AsyncMock()
    manager = _manager(tmp_path, users={"admin": user}, providers={"form_login": provider})
    seeded = Session(
        user_id="admin-01", role="admin", auth_type="assisted_manual", cookies={"session_id": "real"},
        expires_at=datetime.now(timezone.utc) + timedelta(hours=6),
    )

    manager.seed_session(seeded)
    result = await manager.get_session("admin", page=AsyncMock())

    assert result is seeded
    provider.authenticate.assert_not_awaited()
    provider.refresh.assert_not_awaited()


def test_seed_session_persists_to_the_store(tmp_path):
    manager = _manager(tmp_path)
    session = Session(user_id="admin-01", role="admin", auth_type="assisted_manual", cookies={"a": "b"})

    manager.seed_session(session)

    reloaded = SessionManager(users={}, providers={}, store=SessionStore(db_path=tmp_path / "stof.db"))
    assert reloaded._sessions["admin"].cookies == {"a": "b"}


# ---------------------------------------------------------------------------
# Crash-resume: sessions persist across separate manager instances
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_new_manager_reuses_valid_session_from_store_without_reauthenticating(tmp_path):
    db_path = tmp_path / "stof.db"
    user = _user("admin")
    provider = AsyncMock()

    store = SessionStore(db_path=db_path)
    store.save(Session(user_id="admin-01", role="admin", auth_type="form_login"))

    manager = SessionManager(users={"admin": user}, providers={"form_login": provider}, store=SessionStore(db_path=db_path))
    result = await manager.get_session("admin", page=AsyncMock())

    assert result.user_id == "admin-01"
    provider.authenticate.assert_not_awaited()


# ---------------------------------------------------------------------------
# Concurrency — the per-role lock prevents a duplicate authenticate()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_get_session_calls_authenticate_only_once(tmp_path):
    user = _user("admin")
    session = Session(user_id="admin-01", role="admin", auth_type="form_login")

    call_count = 0

    async def slow_authenticate(user, page):
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0.01)
        return session

    provider = AsyncMock()
    provider.authenticate = AsyncMock(side_effect=slow_authenticate)
    manager = _manager(tmp_path, users={"admin": user}, providers={"form_login": provider})

    results = await asyncio.gather(
        manager.get_session("admin", page=AsyncMock()),
        manager.get_session("admin", page=AsyncMock()),
        manager.get_session("admin", page=AsyncMock()),
    )

    assert call_count == 1
    assert all(r is session for r in results)
