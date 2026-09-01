"""Unit tests for Layer 4 — stof.auth.jwt_auth."""
import base64
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthExpiredError, AuthFailedError
from stof.auth.jwt_auth import JWTAuthProvider, decode_jwt_exp
from stof.config.schema import UserConfig
from stof.session.models import Session


def _fake_jwt(exp: datetime | None) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload_dict = {"sub": "admin-01"}
    if exp is not None:
        payload_dict["exp"] = int(exp.timestamp())
    payload = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.signature"


def _user(token: str) -> UserConfig:
    return UserConfig(id="user-01", role="normal", username="jsmith", password=token, auth_type="jwt")


# ---------------------------------------------------------------------------
# Happy path — decode_jwt_exp
# ---------------------------------------------------------------------------


def test_decode_jwt_exp_extracts_expiry():
    exp = datetime(2030, 1, 1, tzinfo=timezone.utc)
    token = _fake_jwt(exp)

    assert decode_jwt_exp(token) == exp


def test_decode_jwt_exp_returns_none_for_malformed_token():
    assert decode_jwt_exp("not-a-jwt") is None


def test_decode_jwt_exp_returns_none_when_no_exp_claim():
    token = _fake_jwt(exp=None)

    assert decode_jwt_exp(token) is None


# ---------------------------------------------------------------------------
# Happy path — authenticate() / is_authenticated()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authenticate_builds_session_from_password_field_token():
    exp = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0)
    token = _fake_jwt(exp)
    provider = JWTAuthProvider()

    session = await provider.authenticate(_user(token), page=AsyncMock())

    assert session.auth_type == "jwt"
    assert session.headers == {"Authorization": f"Bearer {token}"}
    assert session.expires_at == exp


@pytest.mark.asyncio
async def test_authenticate_extracts_token_from_flat_response_field():
    exp = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0)
    token = _fake_jwt(exp)
    provider = JWTAuthProvider(token_url="https://api.example.com/login")
    page = AsyncMock()
    response = AsyncMock(status=200)
    response.json = AsyncMock(return_value={"access_token": token})
    page.request.post = AsyncMock(return_value=response)

    session = await provider.authenticate(_user("placeholder"), page)

    assert session.headers == {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_authenticate_extracts_token_from_nested_response_shape():
    """Regression: a real target's login endpoint (confirmed live)
    wraps the token as {"authentication": {"token": ...}}, not a flat
    "access_token"/"token" field -- the old code silently fell back to
    treating the configured password as if it were the token."""
    exp = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(microsecond=0)
    token = _fake_jwt(exp)
    provider = JWTAuthProvider(token_url="https://api.example.com/login")
    page = AsyncMock()
    response = AsyncMock(status=200)
    response.json = AsyncMock(return_value={"authentication": {"token": token, "bid": 1}})
    page.request.post = AsyncMock(return_value=response)

    session = await provider.authenticate(_user("placeholder"), page)

    assert session.headers == {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_authenticate_sends_both_username_and_email_fields():
    """Real login endpoints disagree on the field name ("username" vs
    "email") -- sending both is harmless (an endpoint expecting one
    just ignores the other) and avoids needing per-target config for
    this specific mismatch."""
    provider = JWTAuthProvider(token_url="https://api.example.com/login")
    page = AsyncMock()
    response = AsyncMock(status=200)
    response.json = AsyncMock(return_value={"token": "placeholder"})
    page.request.post = AsyncMock(return_value=response)

    await provider.authenticate(_user("placeholder"), page)

    call_kwargs = page.request.post.await_args.kwargs
    assert call_kwargs["data"]["username"] == "jsmith"
    assert call_kwargs["data"]["email"] == "jsmith"


@pytest.mark.asyncio
async def test_is_authenticated_true_before_expiry_false_after():
    future = Session(
        user_id="u", role="normal", auth_type="jwt", expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
    )
    past = Session(
        user_id="u", role="normal", auth_type="jwt", expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
    )
    no_expiry = Session(user_id="u", role="normal", auth_type="jwt", expires_at=None)

    provider = JWTAuthProvider()
    page = AsyncMock()

    assert await provider.is_authenticated(future, page) is True
    assert await provider.is_authenticated(past, page) is False
    assert await provider.is_authenticated(no_expiry, page) is True


# ---------------------------------------------------------------------------
# Failure cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authenticate_raises_auth_failed_when_token_url_endpoint_errors():
    provider = JWTAuthProvider(token_url="https://api.example.com/token")
    page = AsyncMock()
    page.request.post = AsyncMock(return_value=AsyncMock(status=401))

    with pytest.raises(AuthFailedError, match="401"):
        await provider.authenticate(_user("placeholder"), page)


@pytest.mark.asyncio
async def test_refresh_raises_auth_expired_when_no_refresh_url_configured():
    provider = JWTAuthProvider()
    session = Session(user_id="u", role="normal", auth_type="jwt")

    with pytest.raises(AuthExpiredError, match="no refresh_url"):
        await provider.refresh(session, AsyncMock())


@pytest.mark.asyncio
async def test_refresh_raises_auth_expired_when_refresh_endpoint_errors():
    provider = JWTAuthProvider(refresh_url="https://api.example.com/refresh")
    session = Session(user_id="u", role="normal", auth_type="jwt", headers={"Authorization": "Bearer old"})
    page = AsyncMock()
    page.request.post = AsyncMock(return_value=AsyncMock(status=403))

    with pytest.raises(AuthExpiredError, match="403"):
        await provider.refresh(session, page)


# ---------------------------------------------------------------------------
# Input validation — refresh() success path updates the session in place
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_updates_session_headers_and_expiry_on_success():
    new_exp = (datetime.now(timezone.utc) + timedelta(hours=2)).replace(microsecond=0)
    new_token = _fake_jwt(new_exp)

    provider = JWTAuthProvider(refresh_url="https://api.example.com/refresh")
    session = Session(
        user_id="u", role="normal", auth_type="jwt", headers={"Authorization": "Bearer old"}, is_valid=False
    )
    page = AsyncMock()
    response = AsyncMock(status=200)
    response.json = AsyncMock(return_value={"access_token": new_token})
    page.request.post = AsyncMock(return_value=response)

    updated = await provider.refresh(session, page)

    assert updated is session
    assert updated.headers["Authorization"] == f"Bearer {new_token}"
    assert updated.expires_at == new_exp
    assert updated.is_valid is True
