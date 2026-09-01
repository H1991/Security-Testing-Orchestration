"""Unit tests for stof.modules.jwt_tests' per-technique layer (TC-057.2
alg:none, TC-057.3 weak-secret brute force, and `run_techniques()`
itself) -- kept in a separate file from `test_jwt_tests.py` since that
one is scoped to `run()`/TC-057.1 only, per its own docstring."""
import base64
import hashlib
import hmac
import json
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthExpiredError, AuthProvider
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.jwt_tests import (
    JwtTestConfig,
    JwtTestsModule,
    decode_jwt_header,
    find_jwks_endpoint,
    find_jwt_in_text,
    find_weak_hmac_secret,
    forge_alg_none_token,
    forge_algorithm_confusion_token,
    forge_kid_injection_token,
    forge_kid_path_traversal_token,
    forge_role_claim_token_signed,
    jwks_hmac_secret,
)
from stof.modules.results import FAIL, NOT_IMPLEMENTED, PASS, SKIPPED
from stof.session.models import Session
from stof.session.session_manager import SessionManager
from stof.session.session_store import SessionStore


def _b64url(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode("ascii")


def _signed_jwt(header: dict, payload: dict, secret: str) -> str:
    signing_input = f"{_b64url(header)}.{_b64url(payload)}".encode()
    signature = base64.urlsafe_b64encode(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{_b64url(header)}.{_b64url(payload)}.{signature}"


# ---------------------------------------------------------------------------
# Pure crypto helpers
# ---------------------------------------------------------------------------


def test_decode_jwt_header_reads_alg():
    token = _signed_jwt({"alg": "HS256", "typ": "JWT"}, {"role": "user"}, "secret")
    assert decode_jwt_header(token)["alg"] == "HS256"


def test_decode_jwt_header_none_for_malformed_token():
    assert decode_jwt_header("not-a-jwt") is None


def test_forge_alg_none_token_sets_alg_none_and_empty_signature():
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "secret")

    forged = forge_alg_none_token(token, "role", "admin")

    header_b64, payload_b64, signature = forged.split(".")
    assert json.loads(base64.urlsafe_b64decode(header_b64 + "=="))["alg"] == "none"
    assert json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))["role"] == "admin"
    assert signature == ""


def test_forge_alg_none_token_none_when_claim_missing():
    token = _signed_jwt({"alg": "HS256"}, {"sub": "123"}, "secret")
    assert forge_alg_none_token(token, "role", "admin") is None


def test_find_weak_hmac_secret_recovers_known_secret():
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "changeme")

    assert find_weak_hmac_secret(token) == "changeme"


def test_find_weak_hmac_secret_none_for_strong_secret():
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "a-very-long-randomly-generated-secret-key")

    assert find_weak_hmac_secret(token) is None


def test_forge_role_claim_token_signed_produces_a_validly_signed_token():
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "secret")

    forged = forge_role_claim_token_signed(token, "role", "admin", "secret")

    header_b64, payload_b64, signature = forged.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_sig = base64.urlsafe_b64encode(hmac.new(b"secret", signing_input, hashlib.sha256).digest()).rstrip(b"=").decode()
    assert signature == expected_sig
    assert json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))["role"] == "admin"


def test_forge_role_claim_token_signed_none_when_claim_missing():
    token = _signed_jwt({"alg": "HS256"}, {"sub": "123"}, "secret")
    assert forge_role_claim_token_signed(token, "role", "admin", "secret") is None


def _rs256_token(payload: dict) -> str:
    """A synthetic RS256-*shaped* token -- the signature isn't a real
    RSA signature (nothing in this module ever verifies it, since the
    whole point of algorithm confusion is that the server also doesn't,
    once handed an HS256-relabelled token), only the header's `alg`
    matters for `_technique_algorithm_confusion`'s own gating."""
    return f"{_b64url({'alg': 'RS256', 'typ': 'JWT'})}.{_b64url(payload)}.notreallyrsasigned"


def _jwks_body(n: str = "AQAB-fake-modulus-bytes") -> str:
    n_b64 = base64.urlsafe_b64encode(n.encode()).rstrip(b"=").decode()
    return json.dumps({"keys": [{"kty": "RSA", "kid": "key-1", "n": n_b64, "e": "AQAB"}]})


def test_find_jwks_endpoint_matches_well_known_path():
    jwks = Endpoint(url="https://x/.well-known/jwks.json", method="GET", endpoint_type="api", auth_required=False)
    other = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", auth_required=True)
    assert find_jwks_endpoint([other, jwks]) is jwks


def test_find_jwks_endpoint_none_when_not_discovered():
    other = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", auth_required=True)
    assert find_jwks_endpoint([other]) is None


def test_jwks_hmac_secret_decodes_modulus_bytes():
    secret = jwks_hmac_secret(_jwks_body("hello-modulus"))
    assert secret == base64.urlsafe_b64decode(base64.urlsafe_b64encode(b"hello-modulus") + b"==")


def test_jwks_hmac_secret_none_for_malformed_body():
    assert jwks_hmac_secret("not json") is None
    assert jwks_hmac_secret(json.dumps({"keys": []})) is None
    assert jwks_hmac_secret(json.dumps({"keys": [{"kty": "RSA"}]})) is None


def test_forge_algorithm_confusion_token_signs_hs256_with_given_key():
    token = _rs256_token({"role": "user"})
    key = b"the-servers-public-key-bytes"

    forged = forge_algorithm_confusion_token(token, "role", "admin", key)

    header_b64, payload_b64, signature = forged.split(".")
    assert json.loads(base64.urlsafe_b64decode(header_b64 + "=="))["alg"] == "HS256"
    assert json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))["role"] == "admin"
    expected_sig = base64.urlsafe_b64encode(
        hmac.new(key, f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    assert signature == expected_sig


def test_forge_algorithm_confusion_token_none_when_claim_missing():
    token = _rs256_token({"sub": "123"})
    assert forge_algorithm_confusion_token(token, "role", "admin", b"key") is None


# ---------------------------------------------------------------------------
# run_techniques() -- async smoke tests
# ---------------------------------------------------------------------------


def _user(role: str) -> UserConfig:
    return UserConfig(id=f"{role}-01", role=role, username=role, password="pw", auth_type="jwt")


class _RoutingProvider(AuthProvider):
    def __init__(self, sessions: dict[str, Session]) -> None:
        self._sessions = sessions

    async def authenticate(self, user, page) -> Session:
        return self._sessions[user.role]

    async def refresh(self, session, page) -> Session:
        raise AuthExpiredError("test fixture: refresh not supported, fall back to authenticate()")

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


def _fake_context(get_side_effect):
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=AsyncMock())
    context.request.get = AsyncMock(side_effect=get_side_effect)
    return context


def _pool_with_context(context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


@pytest.mark.asyncio
async def test_run_techniques_reports_skipped_when_no_endpoint_discovered(tmp_path):
    session_manager = _session_manager(tmp_path, {"user": Session(user_id="u", role="user", auth_type="jwt")})
    pool = _pool_with_context(_fake_context(AsyncMock()))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([], session_manager, pool)

    assert len(results) == 8  # TC-057.1-.8, one role
    assert all(r.status == SKIPPED for r in results)
    assert {r.technique_id for r in results} == {
        "TC-057.1", "TC-057.2", "TC-057.3", "TC-057.4", "TC-057.5", "TC-057.6", "TC-057.7", "TC-057.8",
    }


@pytest.mark.asyncio
async def test_run_techniques_all_pass_when_target_rejects_every_forged_token(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "a-very-long-randomly-generated-secret-key")
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        return _response(403, "denied")

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint], session_manager, pool)

    assert len(results) == 8
    # TC-057.4 SKIPs (not FAILs/PASSes) here: this token's alg is HS256,
    # so algorithm confusion has no surface -- distinct from the other
    # three, which all get a real PASS from the target rejecting them.
    # TC-057.5 SKIPs too: same HS256 token, and its secret isn't one of
    # the common weak candidates, so no validly-signed forged token is
    # recoverable to test claim enforcement with. TC-057.6 SKIPs: no
    # logout_url configured. TC-057.7 PASSes: no JWT-shaped value in
    # the one discovered endpoint URL or in (mocked, empty) storage.
    # TC-057.8 PASSes: every forged 'kid' probe (path-traversal and
    # SQLi-shaped) gets the same "denied" 403 back, and "denied" carries
    # no DB-error fingerprint.
    assert [r.status for r in results] == [PASS, PASS, PASS, SKIPPED, SKIPPED, SKIPPED, PASS, PASS]


@pytest.mark.asyncio
async def test_run_techniques_alg_none_fails_when_target_accepts_it(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "a-very-long-randomly-generated-secret-key")
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        bearer = (headers or {}).get("Authorization", "")
        forged_token = bearer.removeprefix("Bearer ")
        if forged_token.endswith("."):  # alg:none forged tokens end with an empty signature segment
            return _response(200, "Admin dashboard content" * 20)
        return _response(403, "denied")

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.2"].status == FAIL
    assert by_id["TC-057.2"].finding is not None
    assert by_id["TC-057.1"].status == PASS


@pytest.mark.asyncio
async def test_run_techniques_weak_secret_skipped_for_non_hmac_alg(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    # RS256 token: not HMAC, so weak-secret brute force doesn't apply,
    # regardless of what the (fake, unverifiable-here) signature is.
    token = f"{_b64url({'alg': 'RS256'})}.{_b64url({'role': 'user'})}.notreallyrsasigned"
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        return _response(403, "denied")

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.3"].status == SKIPPED
    assert "not HMAC" in by_id["TC-057.3"].detail


@pytest.mark.asyncio
async def test_run_techniques_algorithm_confusion_skipped_when_token_already_hs256(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "a-very-long-randomly-generated-secret-key")
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        return _response(403, "denied")

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.4"].status == SKIPPED
    assert "not asymmetric" in by_id["TC-057.4"].detail


@pytest.mark.asyncio
async def test_run_techniques_algorithm_confusion_skipped_when_no_jwks_discoverable(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    token = _rs256_token({"role": "user"})
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        return _response(403, "denied")

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"])

    # No JWKS-shaped endpoint in the discovered list -- a real, common
    # outcome, not an error.
    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.4"].status == SKIPPED
    assert "no JWKS-shaped endpoint" in by_id["TC-057.4"].detail


@pytest.mark.asyncio
async def test_run_techniques_algorithm_confusion_fails_when_target_accepts_confused_token(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    jwks_endpoint = Endpoint(url="https://x/.well-known/jwks.json", method="GET", endpoint_type="api", parameters=[], auth_required=False)
    token = _rs256_token({"role": "user"})
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})
    jwks_body = _jwks_body()

    async def fake_get(url, headers=None, max_redirects=0):
        if url == jwks_endpoint.url:
            return _response(200, jwks_body)
        bearer = (headers or {}).get("Authorization", "")
        forged_token = bearer.removeprefix("Bearer ")
        if forged_token.count(".") == 2:
            header_segment = forged_token.split(".")[0]
            padding = "=" * (-len(header_segment) % 4)
            try:
                decoded_header = json.loads(base64.urlsafe_b64decode(header_segment + padding))
            except Exception:
                decoded_header = {}
            if decoded_header.get("alg") == "HS256":
                return _response(200, "Admin dashboard content" * 20)
        return _response(403, "denied")

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint, jwks_endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.4"].status == FAIL
    assert by_id["TC-057.4"].finding is not None
    assert jwks_endpoint.url in by_id["TC-057.4"].finding.description
    # The other three techniques operate on this same RS256 token and
    # must be unaffected: TC-057.1/.2 rejected (their forged tokens
    # never carry alg:HS256), TC-057.3 skips outright (not HMAC).
    assert by_id["TC-057.1"].status == PASS
    assert by_id["TC-057.2"].status == PASS
    assert by_id["TC-057.3"].status == SKIPPED


@pytest.mark.asyncio
async def test_run_techniques_algorithm_confusion_passes_when_target_rejects_confused_token(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    jwks_endpoint = Endpoint(url="https://x/.well-known/jwks.json", method="GET", endpoint_type="api", parameters=[], auth_required=False)
    token = _rs256_token({"role": "user"})
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})
    jwks_body = _jwks_body()

    async def fake_get(url, headers=None, max_redirects=0):
        if url == jwks_endpoint.url:
            return _response(200, jwks_body)
        return _response(403, "denied")

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint, jwks_endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.4"].status == PASS
    assert by_id["TC-057.4"].finding is None


class _FormLoginRoutingProvider(AuthProvider):
    def __init__(self, sessions: dict[str, Session]) -> None:
        self._sessions = sessions

    async def authenticate(self, user, page) -> Session:
        return self._sessions[user.role]

    async def refresh(self, session, page) -> Session:
        raise AuthExpiredError("test fixture: refresh not supported, fall back to authenticate()")

    async def is_authenticated(self, session, page) -> bool:
        return True


@pytest.mark.asyncio
async def test_run_techniques_skipped_when_role_not_jwt_authenticated(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    cookie_session = Session(user_id="u", role="user", auth_type="form_login")
    session_manager = SessionManager(
        users={"user": UserConfig(id="u-01", role="user", username="user", password="pw", auth_type="form_login")},
        providers={"form_login": _FormLoginRoutingProvider({"user": cookie_session})},
        store=SessionStore(db_path=tmp_path / "stof.db"),
    )
    pool = _pool_with_context(_fake_context(AsyncMock()))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint], session_manager, pool)

    assert all(r.status == SKIPPED for r in results)
    assert all("not JWT-authenticated" in r.detail for r in results)


# ---------------------------------------------------------------------------
# TC-057.8 -- kid header injection (path traversal + SQLi-signal)
# ---------------------------------------------------------------------------


def test_forge_kid_path_traversal_token_sets_alg_hs256_and_kid_and_verifies_with_empty_secret():
    token = _signed_jwt({"alg": "RS256"}, {"role": "user"}, "irrelevant")

    forged = forge_kid_path_traversal_token(token, "role", "admin", "../../../../dev/null")

    header_b64, payload_b64, signature = forged.split(".")
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
    assert header["alg"] == "HS256"
    assert header["kid"] == "../../../../dev/null"
    assert json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))["role"] == "admin"
    # Signature verifies against the empty-bytes secret -- the presumed
    # content of the traversal target (/dev/null) -- proving the forger
    # actually signed with it, not with something else.
    expected_sig = base64.urlsafe_b64encode(hmac.new(b"", f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    assert signature == expected_sig


def test_forge_kid_path_traversal_token_none_when_role_claim_missing():
    token = _signed_jwt({"alg": "HS256"}, {"sub": "123"}, "s")
    assert forge_kid_path_traversal_token(token, "role", "admin", "../../../../dev/null") is None


def test_forge_kid_injection_token_sets_kid_keeps_payload_and_signature():
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "s")
    original_payload_b64, original_signature = token.split(".")[1], token.split(".")[2]

    forged = forge_kid_injection_token(token, "' OR '1'='1")

    header_b64, payload_b64, signature = forged.split(".")
    assert json.loads(base64.urlsafe_b64decode(header_b64 + "=="))["kid"] == "' OR '1'='1"
    assert payload_b64 == original_payload_b64
    assert signature == original_signature


def test_forge_kid_injection_token_none_for_malformed_token():
    assert forge_kid_injection_token("not-a-jwt", "'") is None


@pytest.mark.asyncio
async def test_kid_header_injection_fails_on_accepted_path_traversal_forgery(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "a-very-long-randomly-generated-secret-key")
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        bearer = (headers or {}).get("Authorization", "")
        forged_token = bearer.removeprefix("Bearer ")
        if forged_token.count(".") == 2:
            header_segment = forged_token.split(".")[0]
            padding = "=" * (-len(header_segment) % 4)
            try:
                header = json.loads(base64.urlsafe_b64decode(header_segment + padding))
            except Exception:
                header = {}
            # Simulate a vulnerable server: it accepts a token whose
            # 'kid' points at the traversal path (the empty-secret
            # signature is exactly what a real vulnerable server would
            # also independently verify, but this fixture just checks
            # the header value stood in for that server-side behavior).
            if header.get("kid", "").endswith("/dev/null"):
                return _response(200, "Admin dashboard content" * 20)
        return _response(403, "denied")

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.8"].status == FAIL
    assert by_id["TC-057.8"].finding is not None
    assert by_id["TC-057.8"].finding.severity == "Critical"
    assert "dev/null" in by_id["TC-057.8"].finding.description


@pytest.mark.asyncio
async def test_kid_header_injection_fails_on_sql_error_fingerprint(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "a-very-long-randomly-generated-secret-key")
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        bearer = (headers or {}).get("Authorization", "")
        forged_token = bearer.removeprefix("Bearer ")
        if forged_token.count(".") == 2:
            header_segment = forged_token.split(".")[0]
            padding = "=" * (-len(header_segment) % 4)
            try:
                header = json.loads(base64.urlsafe_b64decode(header_segment + padding))
            except Exception:
                header = {}
            kid = header.get("kid", "")
            if kid and not kid.endswith("/dev/null"):
                # Path-traversal candidates are rejected (403); the
                # SQLi-shaped 'kid' value trips a simulated DB error.
                return _response(500, "You have an error in your SQL syntax near '''")
        return _response(403, "denied")

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.8"].status == FAIL
    assert by_id["TC-057.8"].finding is not None
    assert by_id["TC-057.8"].finding.severity == "High"
    assert "sql syntax" in by_id["TC-057.8"].finding.response_raw.lower()


@pytest.mark.asyncio
async def test_kid_header_injection_passes_when_target_rejects_both_variants(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "a-very-long-randomly-generated-secret-key")
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        return _response(403, "denied")

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.8"].status == PASS
    assert by_id["TC-057.8"].finding is None
    assert "path-traversal" in by_id["TC-057.8"].detail
    assert "SQLi-shaped" in by_id["TC-057.8"].detail


@pytest.mark.asyncio
async def test_kid_header_injection_path_traversal_half_skipped_when_role_claim_missing(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    token = _signed_jwt({"alg": "HS256"}, {"sub": "123"}, "a-very-long-randomly-generated-secret-key")
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        return _response(403, "denied")

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    # Overall result is still PASS (the SQLi half always runs and found
    # nothing) but the detail is honest that the path-traversal half
    # never actually sent a probe, since 'role' isn't in this payload.
    assert by_id["TC-057.8"].status == PASS
    assert "'role' claim not present -- path-traversal variant skipped" in by_id["TC-057.8"].detail


def test_config_not_implemented_status_exists_for_other_modules_reference():
    # Sanity check that the shared vocabulary import works from this
    # test file too -- NOT_IMPLEMENTED isn't used by jwt_tests itself
    # (all 3 of its techniques are implemented), only by idor_tests.
    assert NOT_IMPLEMENTED == "NOT_IMPLEMENTED"


def test_jwt_test_config_defaults():
    config = JwtTestConfig()
    assert config.role_claim == "role"
    assert config.elevated_value == "admin"
    assert config.logout_url is None


# ---------------------------------------------------------------------------
# find_jwt_in_text -- pure helper, TC-057.7
# ---------------------------------------------------------------------------


def test_find_jwt_in_text_matches_a_real_shaped_token():
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "secret")
    assert find_jwt_in_text(f"https://x/api?access_token={token}") == token


def test_find_jwt_in_text_none_for_plain_url():
    assert find_jwt_in_text("https://x/api/profile?id=42") is None


def test_find_jwt_in_text_does_not_match_short_dot_separated_strings():
    # False-positive guards: a semver string and a hostname are both
    # dot-separated but not remotely JWT-shaped -- neither starts with
    # the base64url encoding of a JSON header ("eyJ"), and even a
    # crafted "eyJ..."-prefixed string needs long-enough segments.
    assert find_jwt_in_text("app version 1.2.3 build 456") is None
    assert find_jwt_in_text("cdn.example.com/assets/app.min.js") is None
    assert find_jwt_in_text("eyJ.short.bit") is None


# ---------------------------------------------------------------------------
# TC-057.5 -- claim validation (exp/nbf/iat/iss/aud enforcement)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_claim_validation_skipped_when_no_signing_capability(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    # Strong secret -> not brute-forceable -> no validly-signed forged
    # token available, so this technique must not fall back to the
    # mismatched-signature shape (that would be indistinguishable from
    # TC-057.1).
    token = _signed_jwt({"alg": "HS256"}, {"role": "user", "exp": 9999999999}, "a-very-long-randomly-generated-secret-key")
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        return _response(403, "denied")

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.5"].status == SKIPPED
    assert "no validly-signed forged token" in by_id["TC-057.5"].detail


@pytest.mark.asyncio
async def test_claim_validation_skipped_when_no_standard_claims_present(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    # Weak secret -> a validly-signed forged token IS recoverable, but
    # this token carries none of exp/nbf/iat/iss/aud -- nothing to
    # tamper with, distinct from the "no signing capability" skip above.
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "changeme")
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        return _response(403, "denied")

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.5"].status == SKIPPED
    assert "none of exp/nbf/iat/iss/aud are present" in by_id["TC-057.5"].detail


@pytest.mark.asyncio
async def test_claim_validation_fails_when_expired_but_validly_signed_token_accepted(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    token = _signed_jwt({"alg": "HS256"}, {"role": "user", "exp": 9999999999}, "changeme")
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        bearer = (headers or {}).get("Authorization", "")
        forged_token = bearer.removeprefix("Bearer ")
        if forged_token == "garbage.invalid.token":
            return _response(401, "unauthorized")
        # The server accepts ANY correctly-HMAC-signed token regardless
        # of 'exp' -- the exact claim-blindness bug this technique
        # proves, distinguishable here from signature rejection because
        # `_signed_jwt`'s helper re-signs with the recovered secret.
        parts = forged_token.split(".")
        if len(parts) == 3:
            return _response(200, "Profile data" * 20)
        return _response(403, "denied")

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.5"].status == FAIL
    assert by_id["TC-057.5"].finding is not None
    assert "exp" in by_id["TC-057.5"].finding.description


@pytest.mark.asyncio
async def test_claim_validation_passes_when_target_enforces_every_tampered_claim(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    token = _signed_jwt({"alg": "HS256"}, {"role": "user", "exp": 9999999999, "aud": "svc-a", "iss": "issuer-a"}, "changeme")
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        return _response(403, "denied")

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.5"].status == PASS
    for claim in ("exp", "aud", "iss"):
        assert claim in by_id["TC-057.5"].detail


# ---------------------------------------------------------------------------
# TC-057.6 -- replay after logout
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_after_logout_skipped_when_no_logout_url_configured(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "s")
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        return _response(403, "denied")

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.6"].status == SKIPPED
    assert "no JWT logout endpoint configured" in by_id["TC-057.6"].detail


@pytest.mark.asyncio
async def test_replay_after_logout_fails_when_old_token_still_accepted(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "s")
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        bearer = (headers or {}).get("Authorization", "")
        if bearer.removeprefix("Bearer ") == "garbage.invalid.token":
            return _response(401, "unauthorized")
        return _response(200, "Profile data" * 20)  # old token still works post-logout

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"], config=JwtTestConfig(logout_url="https://x/logout"))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.6"].status == FAIL
    assert by_id["TC-057.6"].finding is not None
    assert by_id["TC-057.6"].finding.severity == "High"


@pytest.mark.asyncio
async def test_replay_after_logout_passes_when_old_token_rejected(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "s")
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        return _response(401, "unauthorized")  # every request rejected, including the control probe

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"], config=JwtTestConfig(logout_url="https://x/logout"))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.6"].status == PASS


# ---------------------------------------------------------------------------
# TC-057.7 -- JWT exposure (URL / browser storage)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_jwt_exposure_fails_when_token_found_in_discovered_url(tmp_path):
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "s")
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    leaking_endpoint = Endpoint(url=f"https://x/api/data?token={token}", method="GET", endpoint_type="api", parameters=["token"], auth_required=False)
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        return _response(403, "denied")

    pool = _pool_with_context(_fake_context(fake_get))
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint, leaking_endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.7"].status == FAIL
    assert by_id["TC-057.7"].finding is not None
    assert leaking_endpoint.url in by_id["TC-057.7"].finding.response_raw


@pytest.mark.asyncio
async def test_jwt_exposure_fails_when_token_found_in_browser_storage(tmp_path):
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "s")
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        return _response(403, "denied")

    page = AsyncMock()
    page.goto = AsyncMock()
    page.evaluate = AsyncMock(return_value={"localStorage:auth_token": token})
    page.close = AsyncMock()
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=page)
    context.request.get = AsyncMock(side_effect=fake_get)
    pool = _pool_with_context(context)
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.7"].status == FAIL
    assert "localStorage:auth_token" in by_id["TC-057.7"].finding.response_raw


@pytest.mark.asyncio
async def test_jwt_exposure_passes_when_nothing_found(tmp_path):
    token = _signed_jwt({"alg": "HS256"}, {"role": "user"}, "s")
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=[], auth_required=True)
    session = Session(user_id="u", role="user", auth_type="jwt", headers={"Authorization": f"Bearer {token}"})
    session_manager = _session_manager(tmp_path, {"user": session})

    async def fake_get(url, headers=None, max_redirects=0):
        return _response(403, "denied")

    page = AsyncMock()
    page.goto = AsyncMock()
    page.evaluate = AsyncMock(return_value={})
    page.close = AsyncMock()
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=page)
    context.request.get = AsyncMock(side_effect=fake_get)
    pool = _pool_with_context(context)
    module = JwtTestsModule(roles=["user"])

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-057.7"].status == PASS
    assert by_id["TC-057.7"].finding is None
