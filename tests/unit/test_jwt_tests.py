"""Unit tests for Layer 9 — stof.modules.jwt_tests (TC-057 JWT Role
Manipulation only -- scoped to IDOR/Privilege-Escalation work at
explicit user instruction; `alg:none` is deliberately not built here,
see the module docstring)."""
import base64
import json
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthProvider
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.jwt_tests import JwtTestConfig, JwtTestsModule, decode_jwt_payload, forge_role_claim_token
from stof.session.models import Session
from stof.session.session_manager import SessionManager
from stof.session.session_store import SessionStore


def _b64url(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode("ascii")


def _jwt(header: dict, payload: dict, signature: str = "sig") -> str:
    return f"{_b64url(header)}.{_b64url(payload)}.{signature}"


def _user(role: str) -> UserConfig:
    return UserConfig(id=f"{role}-01", role=role, username=role, password="pw", auth_type="jwt")


class _RoutingProvider(AuthProvider):
    def __init__(self, sessions: dict[str, Session]) -> None:
        self._sessions = sessions

    async def authenticate(self, user, page) -> Session:
        return self._sessions[user.role]

    async def refresh(self, session, page) -> Session:
        raise NotImplementedError

    async def is_authenticated(self, session, page) -> bool:
        return True


def _session_manager(tmp_path, sessions: dict[str, Session]) -> SessionManager:
    store = SessionStore(db_path=tmp_path / "stof.db")
    users = {role: _user(role) for role in sessions}
    return SessionManager(users=users, providers={"jwt": _RoutingProvider(sessions)}, store=store)


def _response(status: int, body: str):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    return resp


def _pool_with_get(get_side_effect) -> SessionPool:
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=AsyncMock())
    context.request.get = AsyncMock(side_effect=get_side_effect)
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_decode_jwt_payload_extracts_claims():
    token = _jwt({"alg": "HS256"}, {"sub": "jsmith", "role": "user"})
    assert decode_jwt_payload(token) == {"sub": "jsmith", "role": "user"}


def test_decode_jwt_payload_rejects_malformed_token():
    assert decode_jwt_payload("not-a-jwt") is None


def test_forge_role_claim_token_changes_only_the_claim():
    token = _jwt({"alg": "HS256"}, {"sub": "jsmith", "role": "user"}, signature="realsig")

    forged = forge_role_claim_token(token, "role", "admin")

    header, payload_b64, signature = forged.split(".")
    assert header == token.split(".")[0]  # header untouched
    assert signature == "realsig"  # original (now-mismatched) signature kept
    assert decode_jwt_payload(forged) == {"sub": "jsmith", "role": "admin"}


def test_forge_role_claim_token_returns_none_when_claim_absent():
    token = _jwt({"alg": "HS256"}, {"sub": "jsmith"})
    assert forge_role_claim_token(token, "role", "admin") is None


def test_forge_role_claim_token_supports_nested_dotted_path():
    """Regression: a real target's JWT (confirmed live) nests all
    claims under a wrapper key (payload["data"]["role"]) rather than a
    flat top-level "role" -- the old flat-only lookup could never find
    or tamper with a claim like this."""
    token = _jwt({"alg": "HS256"}, {"data": {"id": 1, "role": "customer"}, "iat": 1})

    forged = forge_role_claim_token(token, "data.role", "admin")

    assert decode_jwt_payload(forged) == {"data": {"id": 1, "role": "admin"}, "iat": 1}


def test_forge_role_claim_token_returns_none_when_nested_path_absent():
    token = _jwt({"alg": "HS256"}, {"data": {"id": 1}})
    assert forge_role_claim_token(token, "data.role", "admin") is None


# ---------------------------------------------------------------------------
# JwtTestsModule.run() — happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_flags_accepted_role_tampered_token(tmp_path):
    token = _jwt({"alg": "HS256"}, {"sub": "jsmith", "role": "user"})
    session = Session(user_id="user-01", role="normal", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"normal": session})
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", auth_required=True)

    async def fake_get(url, headers=None, max_redirects=0):
        if headers and headers.get("Authorization") == "Bearer garbage.invalid.token":
            return _response(401, "unauthorized")
        return _response(200, "profile data" * 20)

    pool = _pool_with_get(fake_get)
    module = JwtTestsModule(roles=["normal"])

    findings = await module.run([endpoint], session_manager, pool)

    assert len(findings) == 1
    assert findings[0].vuln_type == "JWT Role Manipulation"
    assert findings[0].severity == "Critical"
    assert findings[0].user_role == "normal"


@pytest.mark.asyncio
async def test_run_prefers_api_endpoint_over_page_endpoint(tmp_path):
    """Regression: an SPA's page route is typically served regardless
    of auth state (the server has no reason to gate a static app
    shell), so probing one tells us nothing about whether the backend
    verifies JWT claims -- confirmed live, picking a page route made a
    real target's control-token check falsely look "not auth-checked
    at all" and skip. A real "api" endpoint must be preferred when one
    was discovered, even if a page endpoint appears first in the list."""
    token = _jwt({"alg": "HS256"}, {"sub": "jsmith", "role": "user"})
    session = Session(user_id="user-01", role="normal", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"normal": session})
    page_endpoint = Endpoint(url="https://x/#/", method="GET", endpoint_type="page", auth_required=True)
    api_endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", auth_required=True)

    probed_urls: list[str] = []

    async def fake_get(url, headers=None, max_redirects=0):
        probed_urls.append(url)
        if headers and headers.get("Authorization") == "Bearer garbage.invalid.token":
            return _response(401, "unauthorized")
        return _response(200, "profile data" * 20)

    pool = _pool_with_get(fake_get)
    module = JwtTestsModule(roles=["normal"])

    await module.run([page_endpoint, api_endpoint], session_manager, pool)

    assert all(url == "https://x/api/profile" for url in probed_urls)


@pytest.mark.asyncio
async def test_run_populates_evidence_refs_when_collector_supplied(tmp_path):
    token = _jwt({"alg": "HS256"}, {"sub": "jsmith", "role": "user"})
    session = Session(user_id="user-01", role="normal", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"normal": session})
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", auth_required=True)

    async def fake_get(url, headers=None, max_redirects=0):
        if headers and headers.get("Authorization") == "Bearer garbage.invalid.token":
            return _response(401, "unauthorized")
        return _response(200, "profile data" * 20)

    pool = _pool_with_get(fake_get)
    evidence = AsyncMock()
    evidence.capture = AsyncMock(return_value=["data/evidence/scan-1/jwt-role-normal/screenshot.png"])
    module = JwtTestsModule(roles=["normal"])

    findings = await module.run([endpoint], session_manager, pool, evidence=evidence)

    assert len(findings) == 1
    assert findings[0].evidence_refs == ["data/evidence/scan-1/jwt-role-normal/screenshot.png"]
    evidence.capture.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_no_finding_when_tampered_token_rejected(tmp_path):
    token = _jwt({"alg": "HS256"}, {"sub": "jsmith", "role": "user"})
    session = Session(user_id="user-01", role="normal", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"normal": session})
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", auth_required=True)

    async def fake_get(url, headers=None, max_redirects=0):
        return _response(401, "unauthorized")

    pool = _pool_with_get(fake_get)
    module = JwtTestsModule(roles=["normal"])

    findings = await module.run([endpoint], session_manager, pool)

    assert findings == []


# ---------------------------------------------------------------------------
# Input validation / skip conditions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_skips_non_jwt_sessions(tmp_path):
    session = Session(user_id="admin-01", role="admin", auth_type="form_login", cookies={"JSESSIONID": "abc"})
    store = SessionStore(db_path=tmp_path / "stof.db")
    admin_user = UserConfig(id="admin-01", role="admin", username="admin", password="pw", auth_type="form_login")
    session_manager = SessionManager(
        users={"admin": admin_user},
        providers={"form_login": _RoutingProvider({"admin": session})},
        store=store,
    )
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", auth_required=True)
    pool = _pool_with_get(AsyncMock())
    module = JwtTestsModule(roles=["admin"])

    findings = await module.run([endpoint], session_manager, pool)

    assert findings == []


@pytest.mark.asyncio
async def test_run_returns_empty_when_no_auth_required_get_endpoint(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    endpoint = Endpoint(url="https://x/public", method="GET", endpoint_type="page", auth_required=False)
    pool = _pool_with_get(AsyncMock())
    module = JwtTestsModule(roles=["normal"])

    findings = await module.run([endpoint], session_manager, pool)

    assert findings == []


@pytest.mark.asyncio
async def test_run_skips_role_when_endpoint_accepts_garbage_token(tmp_path):
    """Endpoint isn't actually auth-checked at all -- flagging JWT role
    tampering there would be misleading noise, not a JWT-specific bug."""
    token = _jwt({"alg": "HS256"}, {"sub": "jsmith", "role": "user"})
    session = Session(user_id="user-01", role="normal", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"normal": session})
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", auth_required=True)

    call_count = 0

    async def fake_get(url, headers=None, max_redirects=0):
        nonlocal call_count
        call_count += 1
        return _response(200, "public data" * 20)  # accepts anything, including garbage

    pool = _pool_with_get(fake_get)
    module = JwtTestsModule(roles=["normal"])

    findings = await module.run([endpoint], session_manager, pool)

    assert findings == []
    assert call_count == 1  # only the control probe ran, not the role-tampered one


@pytest.mark.asyncio
async def test_run_skips_role_with_malformed_token(tmp_path):
    session = Session(user_id="user-01", role="normal", auth_type="jwt", headers={"Authorization": "Bearer not-a-real-jwt"})
    session_manager = _session_manager(tmp_path, {"normal": session})
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", auth_required=True)
    pool = _pool_with_get(AsyncMock())
    module = JwtTestsModule(roles=["normal"])

    findings = await module.run([endpoint], session_manager, pool)

    assert findings == []


@pytest.mark.asyncio
async def test_run_skips_role_not_configured(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", auth_required=True)
    pool = _pool_with_get(AsyncMock())
    module = JwtTestsModule(roles=["missing-role"])

    findings = await module.run([endpoint], session_manager, pool)

    assert findings == []


@pytest.mark.asyncio
async def test_run_no_role_claim_to_tamper_returns_empty(tmp_path):
    token = _jwt({"alg": "HS256"}, {"sub": "jsmith"})  # no "role" claim at all
    session = Session(user_id="user-01", role="normal", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"normal": session})
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", auth_required=True)

    async def fake_get(url, headers=None, max_redirects=0):
        if headers and headers.get("Authorization") == "Bearer garbage.invalid.token":
            return _response(401, "unauthorized")
        return _response(200, "profile data" * 20)

    pool = _pool_with_get(fake_get)
    module = JwtTestsModule(roles=["normal"], config=JwtTestConfig(role_claim="role"))

    findings = await module.run([endpoint], session_manager, pool)

    assert findings == []
