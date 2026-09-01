"""Unit tests for Layer 9 — stof.modules.session_weakness_tests (TC-129),
the mixin composed into `AuthTestsModule`.

Same mocking conventions as `test_auth_tests.py`/`test_graphql_tests.py`:
a `_RoutingProvider` that hands back pre-built `Session` objects keyed by
role (ignoring the page entirely -- these techniques never actually
drive a real login form), and a `SessionPool` whose single mocked
`Browser.new_context()` return value stands in for every role/anonymous
context the module asks for.
"""
import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from stof.auth.base import AuthExpiredError, AuthProvider
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.auth_tests import AuthTestConfig, AuthTestsModule
from stof.modules.results import ERROR, FAIL, PASS, SKIPPED
from stof.modules.session_weakness_tests import (
    _cookie_flag_issue,
    _cookies_to_playwright,
    _new_or_changed_cookies,
    _session_cookie_did_not_rotate,
    _session_timeout_issue,
    _token_entropy_issue,
)
from stof.session.models import Session
from stof.session.session_manager import SessionManager
from stof.session.session_store import SessionStore


def _user(role: str) -> UserConfig:
    return UserConfig(id=f"{role}-01", role=role, username=f"{role}@x.com", password="pw", auth_type="form_login")


class _RoutingProvider(AuthProvider):
    """Differs from `test_auth_tests.py`/`test_graphql_tests.py`'s own
    `_RoutingProvider` in two ways this module's `_force_fresh_login`
    (invalidate -> re-authenticate) actually exercises, where those
    other test files' single-`get_session()`-per-test usage never did:

    - `authenticate()` returns a deep copy, not the literal preset
      object -- otherwise `SessionManager.invalidate()` mutating the
      cached session's `is_valid` in place would also mutate the
      provider's own preset copy (same object), corrupting every
      later `authenticate()` call for that role within the same test.
    - `refresh()` raises `AuthExpiredError` (matching the real
      `FormLoginProvider.refresh()` contract for a form-based session
      that can't be refreshed in place), not a bare `NotImplementedError`
      -- `SessionManager.get_session()`'s refresh path only treats
      `AuthExpiredError` as "give up, authenticate from scratch"; any
      other exception propagates uncaught.
    """

    def __init__(self, sessions: dict[str, Session]) -> None:
        self._sessions = sessions

    async def authenticate(self, user, page) -> Session:
        return deepcopy(self._sessions[user.role])

    async def refresh(self, session, page) -> Session:
        raise AuthExpiredError(f"session {session.session_id} cannot be refreshed in place")

    async def is_authenticated(self, session, page) -> bool:
        return True


def _session_manager(tmp_path, sessions: dict[str, Session]) -> SessionManager:
    store = SessionStore(db_path=tmp_path / "stof.db")
    users = {role: _user(role) for role in sessions}
    return SessionManager(users=users, providers={"form_login": _RoutingProvider(sessions)}, store=store)


class _SequenceProvider(AuthProvider):
    """Like `_RoutingProvider`, but ALTERNATES between two preset
    `Session`s on successive `authenticate()` calls for a role, cycling
    forever -- needed for TC-129.7/TC-129.8, which force two real
    logins each and compare what each one produced. Other techniques
    in the same `run_techniques()` sweep (TC-129.1/.2/.5/.6) also each
    draw one `authenticate()` call before TC-129.7/.8 get to run, so
    this can't just hand out two items and stop: cycling a period-2
    list guarantees any two CONSECUTIVE draws differ (session_first,
    session_second in some order), regardless of how many draws came
    before -- decoupling this fixture from the exact call count of
    every sibling technique."""

    def __init__(self, sequences: dict[str, list[Session]]) -> None:
        from itertools import cycle
        self._cycles = {role: cycle(seq) for role, seq in sequences.items()}

    async def authenticate(self, user, page) -> Session:
        return deepcopy(next(self._cycles[user.role]))

    async def refresh(self, session, page) -> Session:
        raise AuthExpiredError(f"session {session.session_id} cannot be refreshed in place")

    async def is_authenticated(self, session, page) -> bool:
        return True


def _session_manager_sequence(tmp_path, sequences: dict[str, list[Session]]) -> SessionManager:
    store = SessionStore(db_path=tmp_path / "stof.db")
    users = {role: _user(role) for role in sequences}
    return SessionManager(users=users, providers={"form_login": _SequenceProvider(sequences)}, store=store)


def _response(status: int, body: str):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    return resp


def _pool_with_context(context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


def _zero_count_locator():
    locator = MagicMock()
    locator.count = AsyncMock(return_value=0)
    return locator


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_session_cookie_did_not_rotate_detects_match():
    assert _session_cookie_did_not_rotate({"JSESSIONID": "abc123"}, {"JSESSIONID": "abc123"}) == "JSESSIONID"


def test_session_cookie_did_not_rotate_returns_none_when_value_changed():
    assert _session_cookie_did_not_rotate({"JSESSIONID": "abc123"}, {"JSESSIONID": "xyz999"}) is None


def test_session_cookie_did_not_rotate_returns_none_when_no_shared_name():
    assert _session_cookie_did_not_rotate({"foo": "1"}, {"JSESSIONID": "abc123"}) is None


def test_cookies_to_playwright_shape():
    result = _cookies_to_playwright({"a": "1"}, "https://x.example.com/path")
    assert result == [{"name": "a", "value": "1", "domain": "x.example.com", "path": "/"}]


# ---------------------------------------------------------------------------
# TC-129.5 pure helpers -- cookie security-flag analysis
# ---------------------------------------------------------------------------


def test_new_or_changed_cookies_includes_new_cookie():
    anon = []
    authenticated = [{"name": "JSESSIONID", "value": "abc", "httpOnly": True, "secure": True}]
    assert _new_or_changed_cookies(anon, authenticated) == {"JSESSIONID": authenticated[0]}


def test_new_or_changed_cookies_includes_changed_value():
    anon = [{"name": "JSESSIONID", "value": "pre-login"}]
    authenticated = [{"name": "JSESSIONID", "value": "post-login", "httpOnly": True, "secure": True}]
    assert _new_or_changed_cookies(anon, authenticated) == {"JSESSIONID": authenticated[0]}


def test_new_or_changed_cookies_excludes_unchanged_cookie():
    anon = [{"name": "tracking", "value": "same"}]
    authenticated = [{"name": "tracking", "value": "same"}]
    assert _new_or_changed_cookies(anon, authenticated) == {}


def test_cookie_flag_issue_flags_missing_httponly_first():
    cookie = {"name": "SESSID", "httpOnly": False, "secure": False, "sameSite": "None"}
    issue = _cookie_flag_issue(cookie, is_https_target=True)
    assert "HttpOnly" in issue


def test_cookie_flag_issue_flags_missing_secure_on_https_target():
    cookie = {"name": "SESSID", "httpOnly": True, "secure": False, "sameSite": "Lax"}
    issue = _cookie_flag_issue(cookie, is_https_target=True)
    assert "Secure" in issue


def test_cookie_flag_issue_does_not_flag_missing_secure_on_http_target():
    cookie = {"name": "SESSID", "httpOnly": True, "secure": False, "sameSite": "Lax"}
    assert _cookie_flag_issue(cookie, is_https_target=False) is None


def test_cookie_flag_issue_flags_samesite_none_without_secure():
    cookie = {"name": "SESSID", "httpOnly": True, "secure": False, "sameSite": "None"}
    issue = _cookie_flag_issue(cookie, is_https_target=False)
    assert "SameSite=None" in issue


def test_cookie_flag_issue_does_not_flag_samesite_missing_entirely():
    """False-positive guard: SameSite absent is NOT a finding (modern
    browsers default to Lax)."""
    cookie = {"name": "SESSID", "httpOnly": True, "secure": True, "sameSite": None}
    assert _cookie_flag_issue(cookie, is_https_target=True) is None


def test_cookie_flag_issue_passes_fully_flagged_cookie():
    cookie = {"name": "SESSID", "httpOnly": True, "secure": True, "sameSite": "Lax"}
    assert _cookie_flag_issue(cookie, is_https_target=True) is None


# ---------------------------------------------------------------------------
# TC-129.1 — session ID doesn't rotate on login
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_129_1_skipped_when_no_test_role_configured(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.1"].status == SKIPPED
    assert "test_role" in by_id["TC-129.1"].detail


@pytest.mark.asyncio
async def test_129_1_skipped_when_no_target_url_configured(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(test_role="normal"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.1"].status == SKIPPED
    assert "target URL" in by_id["TC-129.1"].detail


@pytest.mark.asyncio
async def test_129_1_error_when_probe_fails(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    context.request.get = AsyncMock(side_effect=Exception("no network in this test"))
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login", test_role="normal"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.1"].status == ERROR


@pytest.mark.asyncio
async def test_129_1_fails_when_cookie_value_unchanged_across_login(tmp_path):
    session_manager = _session_manager(
        tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "fixed-abc123"})}
    )
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "welcome"))
    context.cookies = AsyncMock(return_value=[{"name": "JSESSIONID", "value": "fixed-abc123"}])
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login", test_role="normal"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.1"].status == FAIL
    assert by_id["TC-129.1"].finding is not None
    assert "JSESSIONID" in by_id["TC-129.1"].finding.description


@pytest.mark.asyncio
async def test_129_1_passes_when_cookie_rotates(tmp_path):
    session_manager = _session_manager(
        tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "post-login-xyz"})}
    )
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "welcome"))
    context.cookies = AsyncMock(return_value=[{"name": "JSESSIONID", "value": "pre-login-abc"}])
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login", test_role="normal"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.1"].status == PASS


@pytest.mark.asyncio
async def test_129_1_skipped_when_authenticated_session_has_no_cookies(tmp_path):
    session_manager = _session_manager(
        tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="jwt", cookies={})}
    )
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "welcome"))
    context.cookies = AsyncMock(return_value=[])
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login", test_role="normal"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.1"].status == SKIPPED
    assert "no cookies" in by_id["TC-129.1"].detail


# ---------------------------------------------------------------------------
# TC-129.2 — session remains valid after logout
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_129_2_skipped_when_no_test_role_configured(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig())

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.2"].status == SKIPPED


@pytest.mark.asyncio
async def test_129_2_skipped_when_no_target_url_available(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(test_role="normal"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.2"].status == SKIPPED
    assert "no discovered endpoint" in by_id["TC-129.2"].detail


@pytest.mark.asyncio
async def test_129_2_skipped_when_session_has_no_cookies(tmp_path):
    endpoint = Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page")
    session_manager = _session_manager(
        tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="jwt", cookies={})}
    )
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(test_role="normal"))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.2"].status == SKIPPED
    assert "no cookies" in by_id["TC-129.2"].detail


@pytest.mark.asyncio
async def test_129_2_skipped_when_no_logout_mechanism_found(tmp_path):
    endpoint = Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page")
    session_manager = _session_manager(
        tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "abc123"})}
    )
    page = AsyncMock()
    page.goto = AsyncMock()
    page.locator = MagicMock(return_value=_zero_count_locator())
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=page)
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(test_role="normal"))  # no logout_url configured

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.2"].status == SKIPPED
    assert "no logout mechanism" in by_id["TC-129.2"].detail


@pytest.mark.asyncio
async def test_129_2_fails_when_old_cookie_still_authenticates_after_logout(tmp_path):
    endpoint = Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page")
    session_manager = _session_manager(
        tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "abc123"})}
    )
    page = AsyncMock()
    page.goto = AsyncMock()
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=page)
    # Still-authenticated, substantial-body response with no denial markers
    context.request.get = AsyncMock(return_value=_response(200, "your account dashboard " * 20))
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(test_role="normal", logout_url="https://x/logout"))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.2"].status == FAIL
    assert by_id["TC-129.2"].finding is not None


@pytest.mark.asyncio
async def test_129_2_passes_when_old_cookie_denied_after_logout(tmp_path):
    endpoint = Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page")
    session_manager = _session_manager(
        tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "abc123"})}
    )
    page = AsyncMock()
    page.goto = AsyncMock()
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=page)
    context.request.get = AsyncMock(return_value=_response(401, "unauthorized"))
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(test_role="normal", logout_url="https://x/logout"))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.2"].status == PASS


@pytest.mark.asyncio
async def test_129_2_logs_out_via_generic_selector_when_no_logout_url_configured(tmp_path):
    endpoint = Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page")
    session_manager = _session_manager(
        tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "abc123"})}
    )

    matching_locator = MagicMock()
    matching_locator.count = AsyncMock(return_value=1)
    matching_locator.first.click = AsyncMock()

    def fake_locator(selector):
        return matching_locator if "Sign Off" in selector else _zero_count_locator()

    page = AsyncMock()
    page.goto = AsyncMock()
    page.locator = MagicMock(side_effect=fake_locator)
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=page)
    context.request.get = AsyncMock(return_value=_response(401, "unauthorized"))
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(test_role="normal"))  # no logout_url -- generic fallback

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.2"].status == PASS
    matching_locator.first.click.assert_awaited_once()


# ---------------------------------------------------------------------------
# TC-129.3 — no rate limiting / lockout on login
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_129_3_skipped_when_no_login_endpoint_configured(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig())

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.3"].status == SKIPPED


@pytest.mark.asyncio
async def test_129_3_fails_when_no_signal_across_every_attempt(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(404, "not found"))
    context.request.post = AsyncMock(return_value=_response(401, json.dumps({"error": "invalid credentials"})))
    pool = _pool_with_context(context)
    # credential_pairs=() keeps TC-022.1's own POST loop (also enabled by
    # login_json_endpoint) from contributing extra calls to the
    # `context.request.post` count this test asserts on.
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login", credential_pairs=()))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.3"].status == FAIL
    assert by_id["TC-129.3"].finding is not None
    assert context.request.post.await_count == 6


@pytest.mark.asyncio
async def test_129_3_passes_and_stops_early_on_429(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(404, "not found"))
    call_count = {"n": 0}

    async def fake_post(url, data=None, headers=None):
        call_count["n"] += 1
        if call_count["n"] >= 3:
            return _response(429, "too many requests")
        return _response(401, json.dumps({"error": "invalid credentials"}))

    context.request.post = AsyncMock(side_effect=fake_post)
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login", credential_pairs=()))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.3"].status == PASS
    assert call_count["n"] == 3  # stopped as soon as the 429 was observed


@pytest.mark.asyncio
async def test_129_3_passes_on_captcha_shaped_body_without_429(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(404, "not found"))
    context.request.post = AsyncMock(return_value=_response(200, "Please complete the CAPTCHA to continue"))
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login", credential_pairs=()))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.3"].status == PASS
    assert context.request.post.await_count == 1  # stopped on the very first attempt


@pytest.mark.asyncio
async def test_129_3_falls_back_to_discovered_html_form_and_fails_when_no_signal(tmp_path):
    """No `login_json_endpoint` configured, but a discovered HTML login
    form -- should run against that form instead of SKIPping, same
    fallback treatment as TC-022.1/TC-027.5."""
    login_endpoint = Endpoint(
        url="https://x/doLogin", method="POST", endpoint_type="form",
        parameters=["uid", "passw"], param_locations={"uid": "body", "passw": "body"},
    )
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(200, "Invalid username or password"))
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(credential_pairs=()))  # no login_json_endpoint configured

    results = await module.run_techniques([login_endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.3"].status == FAIL
    assert by_id["TC-129.3"].finding is not None
    # 6 rate-limit attempts + 1 baseline probe from TC-022.1's own
    # discovered-HTML-form fallback (also enabled by the same discovered
    # `login_endpoint`, with an empty `credential_pairs` sweep) sharing
    # this same mocked POST.
    assert context.request.post.await_count == 7


@pytest.mark.asyncio
async def test_129_3_still_skips_when_no_json_endpoint_and_no_discovered_form(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig())

    page_endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    results = await module.run_techniques([page_endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.3"].status == SKIPPED


# ---------------------------------------------------------------------------
# TC-129.4 — session remains valid after a password change
# ---------------------------------------------------------------------------


def _129_4_config(**overrides) -> AuthTestConfig:
    defaults = dict(
        test_role="normal",
        change_password_url="https://x/rest/user/change-password",
        test_current_password="OldPw!123",
        allow_state_changing_probes=True,
    )
    defaults.update(overrides)
    return AuthTestConfig(**defaults)


@pytest.mark.asyncio
async def test_129_4_skipped_when_gate_off(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=_129_4_config(allow_state_changing_probes=False))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.4"].status == SKIPPED
    assert "disabled by default" in by_id["TC-129.4"].detail


@pytest.mark.asyncio
async def test_129_4_skipped_when_config_missing(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(allow_state_changing_probes=True))  # no change_password_url/test_role/test_current_password

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.4"].status == SKIPPED
    assert "change_password_url" in by_id["TC-129.4"].detail


@pytest.mark.asyncio
async def test_129_4_fails_when_old_cookie_still_authenticates_after_password_change(tmp_path):
    endpoint = Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page")
    session_manager = _session_manager(
        tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "abc123"})}
    )
    context = AsyncMock()
    # GET-style change-password probe accepted (HTTP < 400).
    context.request.get = AsyncMock(return_value=_response(200, "your account dashboard " * 20))
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=_129_4_config())

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.4"].status == FAIL
    assert by_id["TC-129.4"].finding is not None
    assert "password change" in by_id["TC-129.4"].finding.description


@pytest.mark.asyncio
async def test_129_4_passes_when_old_cookie_denied_after_password_change(tmp_path):
    endpoint = Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page")
    session_manager = _session_manager(
        tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "abc123"})}
    )

    async def fake_get(url, **kwargs):
        if url == "https://x/rest/user/change-password":
            return _response(200, "password changed")
        return _response(401, "unauthorized")

    context = AsyncMock()
    context.request.get = AsyncMock(side_effect=fake_get)
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=_129_4_config())

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.4"].status == PASS


# ---------------------------------------------------------------------------
# TC-129.5 — session/auth cookie missing security flags
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_129_5_skipped_when_no_test_role_configured(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.5"].status == SKIPPED


@pytest.mark.asyncio
async def test_129_5_fails_on_missing_httponly(tmp_path):
    session_manager = _session_manager(
        tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "post-login"})}
    )
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "welcome"))
    context.cookies = AsyncMock(side_effect=[
        [],  # TC-129.1's own anon-jar cookies() call, ahead of TC-129.5 in run_techniques()
        [],  # TC-129.5's anon jar -- no cookie yet
        [{"name": "JSESSIONID", "value": "post-login", "httpOnly": False, "secure": True, "sameSite": "Lax"}],
    ])
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login", test_role="normal"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.5"].status == FAIL
    assert by_id["TC-129.5"].finding is not None
    assert "HttpOnly" in by_id["TC-129.5"].finding.description
    assert "JSESSIONID" in by_id["TC-129.5"].finding.description


@pytest.mark.asyncio
async def test_129_5_fails_on_missing_secure_on_https_target(tmp_path):
    session_manager = _session_manager(
        tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "post-login"})}
    )
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "welcome"))
    context.cookies = AsyncMock(side_effect=[
        [],
        [],
        [{"name": "JSESSIONID", "value": "post-login", "httpOnly": True, "secure": False, "sameSite": "Lax"}],
    ])
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login", test_role="normal"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.5"].status == FAIL
    assert "Secure" in by_id["TC-129.5"].finding.description


@pytest.mark.asyncio
async def test_129_5_fails_on_samesite_none_without_secure(tmp_path):
    session_manager = _session_manager(
        tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "post-login"})}
    )
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "welcome"))
    context.cookies = AsyncMock(side_effect=[
        [],
        [],
        [{"name": "JSESSIONID", "value": "post-login", "httpOnly": True, "secure": False, "sameSite": "None"}],
    ])
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="http://x/rest/login", test_role="normal"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.5"].status == FAIL
    assert "SameSite=None" in by_id["TC-129.5"].finding.description


@pytest.mark.asyncio
async def test_129_5_passes_when_session_cookie_fully_flagged(tmp_path):
    session_manager = _session_manager(
        tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "post-login"})}
    )
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "welcome"))
    context.cookies = AsyncMock(side_effect=[
        [],
        [],
        [{"name": "JSESSIONID", "value": "post-login", "httpOnly": True, "secure": True, "sameSite": "Lax"}],
    ])
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login", test_role="normal"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.5"].status == PASS


@pytest.mark.asyncio
async def test_129_5_skipped_when_no_new_or_changed_cookie(tmp_path):
    session_manager = _session_manager(
        tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login", cookies={"tracking": "same"})}
    )
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "welcome"))
    context.cookies = AsyncMock(side_effect=[
        [{"name": "tracking", "value": "same"}],  # TC-129.1's own anon-jar cookies() call
        [{"name": "tracking", "value": "same"}],
        [{"name": "tracking", "value": "same", "httpOnly": False, "secure": False, "sameSite": None}],
    ])
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login", test_role="normal"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.5"].status == SKIPPED
    assert "no cookie was newly issued or changed" in by_id["TC-129.5"].detail


# ---------------------------------------------------------------------------
# TC-129.6 pure helper -- session timeout observability
# ---------------------------------------------------------------------------


def test_session_timeout_issue_none_when_within_bound():
    created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    expires = created + timedelta(hours=6)
    assert _session_timeout_issue(created, expires) is None


def test_session_timeout_issue_flags_unbounded_expiry():
    created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    expires = created + timedelta(hours=100)
    issue = _session_timeout_issue(created, expires)
    assert issue is not None
    assert "100.0 hours" in issue


# ---------------------------------------------------------------------------
# TC-129.8 pure helper -- session token entropy analysis
# ---------------------------------------------------------------------------


def test_token_entropy_issue_none_for_identical_values():
    """False-positive guard: identical values across logins is
    TC-129.1's session-fixation finding, not an entropy finding."""
    assert _token_entropy_issue("same-token-value-123456", "same-token-value-123456") is None


def test_token_entropy_issue_flags_short_token():
    issue = _token_entropy_issue("abc123", "xyz789")
    assert issue is not None
    assert "characters long" in issue


def test_token_entropy_issue_flags_shared_prefix():
    issue = _token_entropy_issue("sessiontoken-AAAA1111", "sessiontoken-BBBB2222")
    assert issue is not None
    assert "prefix" in issue


def test_token_entropy_issue_flags_sequential_numeric():
    issue = _token_entropy_issue("100045782301923456", "100045782301923460")
    assert issue is not None
    assert "sequential" in issue


def test_token_entropy_issue_flags_low_charset():
    issue = _token_entropy_issue("aaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbb")
    assert issue is not None
    assert "distinct character" in issue


def test_token_entropy_issue_does_not_flag_random_looking_tokens():
    """False-positive guard: two genuinely random, high-variety,
    non-numeric, non-shared-prefix tokens must not be flagged."""
    issue = _token_entropy_issue(
        "f3a9c81e7b6d4502af19e0c3d8b7654321fe0a9",
        "9c1b7e2a04f6d83c519a0e7b2d4f68901ac3e75",
    )
    assert issue is None


# ---------------------------------------------------------------------------
# TC-129.6 -- session timeout / expiry not observable or unbounded
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_129_6_skipped_when_no_test_role_configured(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.6"].status == SKIPPED


@pytest.mark.asyncio
async def test_129_6_skipped_when_no_target_url_configured(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(test_role="normal"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.6"].status == SKIPPED
    assert "login_json_endpoint" in by_id["TC-129.6"].detail


@pytest.mark.asyncio
async def test_129_6_skipped_when_no_expiry_observable(tmp_path):
    """Honest, by-design SKIP: no live-wait test is fabricated when the
    target exposes no expiry information at all."""
    session_manager = _session_manager(
        tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "abc"}, expires_at=None)}
    )
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login", test_role="normal"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.6"].status == SKIPPED
    assert "no expiry information observable" in by_id["TC-129.6"].detail


@pytest.mark.asyncio
async def test_129_6_passes_when_expiry_within_bound(tmp_path):
    created = datetime.now(timezone.utc)
    session_manager = _session_manager(
        tmp_path, {"normal": Session(
            user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "abc"},
            created_at=created, expires_at=created + timedelta(hours=4),
        )}
    )
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login", test_role="normal"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.6"].status == PASS


@pytest.mark.asyncio
async def test_129_6_fails_when_expiry_unbounded(tmp_path):
    created = datetime.now(timezone.utc)
    session_manager = _session_manager(
        tmp_path, {"normal": Session(
            user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "abc"},
            created_at=created, expires_at=created + timedelta(days=30),
        )}
    )
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login", test_role="normal"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.6"].status == FAIL
    assert by_id["TC-129.6"].finding is not None


# ---------------------------------------------------------------------------
# TC-129.7 -- concurrent sessions not revoked on a second login
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_129_7_skipped_when_no_test_role_configured(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig())

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.7"].status == SKIPPED


@pytest.mark.asyncio
async def test_129_7_skipped_when_session_has_no_cookies(tmp_path):
    endpoint = Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page")
    session_manager = _session_manager(
        tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="jwt", cookies={})}
    )
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(test_role="normal"))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.7"].status == SKIPPED
    assert "no cookies" in by_id["TC-129.7"].detail


@pytest.mark.asyncio
async def test_129_7_fails_when_first_session_still_authenticates_after_second_login(tmp_path):
    endpoint = Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page")
    sequence = [
        Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "first-session-abc"}),
        Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "second-session-xyz"}),
    ]
    session_manager = _session_manager_sequence(tmp_path, {"normal": sequence})
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "your account dashboard " * 20))
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(test_role="normal"))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.7"].status == FAIL
    assert by_id["TC-129.7"].finding is not None


@pytest.mark.asyncio
async def test_129_7_passes_when_first_session_revoked_after_second_login(tmp_path):
    endpoint = Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page")
    sequence = [
        Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "first-session-abc"}),
        Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "second-session-xyz"}),
    ]
    session_manager = _session_manager_sequence(tmp_path, {"normal": sequence})
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(401, "unauthorized"))
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(test_role="normal"))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.7"].status == PASS


@pytest.mark.asyncio
async def test_129_7_error_when_replay_probe_fails(tmp_path):
    """False-positive guard: a transient probe failure on the replay
    must surface as ERROR, never silently degrade into a PASS."""
    endpoint = Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page")
    sequence = [
        Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "first-session-abc"}),
        Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "second-session-xyz"}),
    ]
    session_manager = _session_manager_sequence(tmp_path, {"normal": sequence})
    context = AsyncMock()
    context.request.get = AsyncMock(side_effect=Exception("ERR_CONNECTION_RESET"))
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig(test_role="normal"))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.7"].status == ERROR


# ---------------------------------------------------------------------------
# TC-129.8 -- session token low entropy / predictable structure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_129_8_skipped_when_no_test_role_configured(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig())

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.8"].status == SKIPPED


@pytest.mark.asyncio
async def test_129_8_skipped_when_no_shared_cookie_name(tmp_path):
    endpoint = Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page")
    sequence = [
        Session(user_id="u", role="normal", auth_type="form_login", cookies={"FIRSTNAME": "abc"}),
        Session(user_id="u", role="normal", auth_type="form_login", cookies={"SECONDNAME": "xyz"}),
    ]
    session_manager = _session_manager_sequence(tmp_path, {"normal": sequence})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(test_role="normal"))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.8"].status == SKIPPED
    assert "no cookie name observed in both" in by_id["TC-129.8"].detail


@pytest.mark.asyncio
async def test_129_8_fails_on_sequential_numeric_token(tmp_path):
    endpoint = Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page")
    sequence = [
        Session(user_id="u", role="normal", auth_type="form_login", cookies={"SESSID": "100045782301923456"}),
        Session(user_id="u", role="normal", auth_type="form_login", cookies={"SESSID": "100045782301923460"}),
    ]
    session_manager = _session_manager_sequence(tmp_path, {"normal": sequence})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(test_role="normal"))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.8"].status == FAIL
    assert by_id["TC-129.8"].finding is not None
    assert "sequential" in by_id["TC-129.8"].finding.description


@pytest.mark.asyncio
async def test_129_8_passes_on_random_looking_tokens(tmp_path):
    """False-positive guard, exercised at the full-technique level: two
    legitimately random, high-variety session tokens must PASS, not FAIL."""
    endpoint = Endpoint(url="https://x/dashboard", method="GET", endpoint_type="page")
    sequence = [
        Session(user_id="u", role="normal", auth_type="form_login",
                cookies={"SESSID": "f3a9c81e7b6d4502af19e0c3d8b7654321fe0a9"}),
        Session(user_id="u", role="normal", auth_type="form_login",
                cookies={"SESSID": "9c1b7e2a04f6d83c519a0e7b2d4f68901ac3e75"}),
    ]
    session_manager = _session_manager_sequence(tmp_path, {"normal": sequence})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(test_role="normal"))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-129.8"].status == PASS
