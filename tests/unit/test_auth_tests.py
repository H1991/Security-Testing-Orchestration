"""Unit tests for Layer 9 — stof.modules.auth_tests (TC-022, TC-025, TC-027)."""
import json
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthProvider
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.auth_tests import AuthTestConfig, AuthTestsModule, _confidence_from_relogin, _looks_form_authenticated
from stof.modules.results import ERROR, FAIL, NOT_IMPLEMENTED, PASS, SKIPPED
from stof.session.models import Session
from stof.session.session_manager import SessionManager
from stof.session.session_store import SessionStore


# ---------------------------------------------------------------------------
# _looks_form_authenticated -- JSON API login responses (e.g. this
# project's own Juice Shop benchmark target, which answers a login
# attempt with a JSON body carrying a token, never an HTML redirect).
# ---------------------------------------------------------------------------


def test_looks_form_authenticated_true_on_json_body_carrying_a_token():
    assert _looks_form_authenticated(
        200, {}, '{"authentication":{"token":"eyJhbGciOiJSUzI1NiJ9.abc.def"}}',
        200, {}, '{"error":{"message":"Invalid email or password."}}',
    )


def test_looks_form_authenticated_false_when_both_json_responses_are_errors():
    assert not _looks_form_authenticated(
        200, {}, '{"error":{"message":"Invalid email or password."}}',
        200, {}, '{"error":{"message":"Invalid email or password."}}',
    )


def test_confidence_from_relogin_true_means_confirmed():
    assert _confidence_from_relogin(True) == "confirmed"


def test_confidence_from_relogin_none_means_likely():
    assert _confidence_from_relogin(None) == "likely"


def _user(role: str) -> UserConfig:
    return UserConfig(id=f"{role}-01", role=role, username=f"{role}@x.com", password="pw", auth_type="form_login")


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
    return SessionManager(users=users, providers={"form_login": _RoutingProvider(sessions)}, store=store)


def _response(status: int, body: str, headers: dict | None = None):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    resp.headers = headers or {}
    return resp


def _pool_with_context(context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


# ---------------------------------------------------------------------------
# TC-022 Default Credentials
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_default_credentials_fails_when_a_pair_is_accepted(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()

    async def fake_post(url, data=None, headers=None):
        payload = json.loads(data)
        accepted = payload["username"] == "admin" and payload["password"] == "admin"
        body = {"token": "abc"} if accepted else {"error": "invalid"}
        return _response(200 if accepted else 401, json.dumps(body))

    context.request.post = AsyncMock(side_effect=fake_post)
    context.request.get = AsyncMock(return_value=_response(200, "a generic homepage"))
    pool = _pool_with_context(context)
    config = AuthTestConfig(login_json_endpoint="https://x/rest/user/login", credential_pairs=(("admin", "admin"),))
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-022.1"].status == FAIL
    assert by_id["TC-022.1"].finding is not None
    assert "***" in by_id["TC-022.1"].finding.request_raw  # password never logged in plaintext


@pytest.mark.asyncio
async def test_default_credentials_passes_when_none_accepted(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(401, '{"error": "invalid"}'))
    context.request.get = AsyncMock(return_value=_response(200, "a generic homepage"))
    pool = _pool_with_context(context)
    config = AuthTestConfig(login_json_endpoint="https://x/rest/user/login", credential_pairs=(("admin", "admin"),))
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-022.1"].status == PASS


@pytest.mark.asyncio
async def test_default_credentials_skipped_when_no_login_endpoint_configured(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig())

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-022.1"].status == SKIPPED


@pytest.mark.asyncio
async def test_022_2_3_4_skip_cleanly_when_unconfigured(tmp_path):
    """No endpoints and no login_json_endpoint configured -- each
    technique should report SKIPPED (there's nothing to fingerprint or
    probe), not crash or silently vanish."""
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()
    context.request.get = AsyncMock(side_effect=Exception("no network in this test"))
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig())

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-022.2"].status == SKIPPED
    assert by_id["TC-022.3"].status == SKIPPED
    assert by_id["TC-022.4"].status == SKIPPED


@pytest.mark.asyncio
async def test_022_2_vendor_defaults_fails_when_fingerprint_and_credential_match(tmp_path):
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()

    async def fake_get(url, max_redirects=0):
        return _response(200, "Welcome to Tomcat", headers={"server": "Apache-Coyote/1.1"})

    async def fake_post(url, data=None, headers=None):
        payload = json.loads(data)
        accepted = payload["username"] == "tomcat" and payload["password"] == "tomcat"
        return _response(200 if accepted else 401, '{"token": "abc"}' if accepted else '{"error": "no"}')

    context.request.get = AsyncMock(side_effect=fake_get)
    context.request.post = AsyncMock(side_effect=fake_post)
    pool = _pool_with_context(context)
    config = AuthTestConfig(login_json_endpoint="https://x/rest/user/login")
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-022.2"].status == FAIL
    assert by_id["TC-022.2"].finding is not None
    assert "tomcat" in by_id["TC-022.2"].finding.description.lower()


@pytest.mark.asyncio
async def test_022_3_admin_interface_defaults_passes_when_no_admin_path_reachable(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(404, "not found"))
    pool = _pool_with_context(context)
    config = AuthTestConfig(login_json_endpoint="https://x/rest/user/login")
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-022.3"].status == PASS


@pytest.mark.asyncio
async def test_022_3_admin_interface_defaults_passes_on_spa_catchall_that_serves_200_for_any_path(tmp_path):
    """A client-side-routed SPA serves an identical index.html shell --
    HTTP 200, same bytes -- for ANY unmatched path, including every
    candidate in _ADMIN_PANEL_LOGIN_PATHS AND the technique's own random
    control probe. Without a baseline comparison this would look like
    every admin path is "reachable"; with it, PASS is correct."""
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(200, "<html>spa shell</html>" * 20))
    pool = _pool_with_context(context)
    config = AuthTestConfig(login_json_endpoint="https://x/rest/user/login")
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-022.3"].status == PASS


@pytest.mark.asyncio
async def test_022_4_default_api_keys_fails_when_key_pattern_found(tmp_path):
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()

    async def fake_get(url, max_redirects=0):
        if url.endswith("/.env"):
            return _response(200, 'API_KEY="sk_live_abcdefghijklmnopqrstuvwx"')
        return _response(404, "not found")

    context.request.get = AsyncMock(side_effect=fake_get)
    pool = _pool_with_context(context)
    module = AuthTestsModule(config=AuthTestConfig())

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-022.4"].status == FAIL


# ---------------------------------------------------------------------------
# TC-025 Weak Password Policy — gating and revert
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_weak_password_techniques_skipped_by_default(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(AsyncMock())
    config = AuthTestConfig(change_password_url="https://x/rest/user/change-password", test_role="normal", test_current_password="oldpw")
    module = AuthTestsModule(config=config)  # allow_state_changing_probes defaults False

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    for tid in ("TC-025.1", "TC-025.2", "TC-025.3"):
        assert by_id[tid].status == SKIPPED
        assert "disabled by default" in by_id[tid].detail


@pytest.mark.asyncio
async def test_weak_password_accepted_fails_and_reverts(tmp_path):
    """`change_password_url` being configured enables 4 techniques at
    once (TC-025.1/.2/.3 and TC-027.4), each independently set+revert
    against the same endpoint -- this test isolates TC-025.1's own
    set/revert pair (candidate "abc12") out of that shared traffic."""
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    change_calls: list[dict] = []

    async def fake_get(url, params=None, max_redirects=0):
        change_calls.append(params)
        return _response(200, "ok")

    context.request.get = AsyncMock(side_effect=fake_get)
    pool = _pool_with_context(context)
    config = AuthTestConfig(
        change_password_url="https://x/rest/user/change-password", test_role="normal",
        test_current_password="oldpw", short_passwords=("abc12",), allow_state_changing_probes=True,
    )
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-025.1"].status == FAIL
    assert by_id["TC-025.1"].finding is not None

    # `change_calls` also picks up TC-129.1's cookie-rotation probe (a
    # plain GET against `change_password_url`, the only target URL this
    # test configures) -- that call has no `params` at all, so it's
    # filtered out here rather than assumed to be a change-password call.
    abc12_calls = [c for c in change_calls if c and (c.get("new") == "abc12" or c.get("current") == "abc12")]
    assert len(abc12_calls) == 2  # set to "abc12", then revert back to "oldpw"
    assert abc12_calls[0]["new"] == "abc12"
    assert abc12_calls[1] == {"current": "abc12", "new": "oldpw", "repeat": "oldpw"}


@pytest.mark.asyncio
async def test_weak_password_confirmed_via_relogin_when_login_endpoint_configured(tmp_path):
    """When `login_json_endpoint`/`test_username` are configured, a
    weak-password-accepted finding is confirmed by actually logging in
    with the new password, not just trusted from the change-password
    endpoint's status code."""
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()

    async def fake_get(url, params=None, max_redirects=0):
        return _response(200, "ok")

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        return _response(200, json.dumps({"token": "eyFakeJWT"}))

    context.request.get = AsyncMock(side_effect=fake_get)
    context.request.post = AsyncMock(side_effect=fake_post)
    pool = _pool_with_context(context)
    config = AuthTestConfig(
        change_password_url="https://x/rest/user/change-password", test_role="normal",
        test_current_password="oldpw", short_passwords=("abc12",), allow_state_changing_probes=True,
        login_json_endpoint="https://x/rest/user/login", test_username="normal@x.com",
    )
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-025.1"].status == FAIL
    assert "CONFIRMED" in by_id["TC-025.1"].finding.description


@pytest.mark.asyncio
async def test_weak_password_accepted_downgrades_to_pass_when_relogin_fails(tmp_path):
    """The core false-positive-prevention fix: a change-password
    endpoint returning a non-error status doesn't necessarily mean the
    password really changed. Confirmed here by a failed re-login,
    which must downgrade the finding to PASS instead of a Critical
    FAIL -- the same class of fix already applied to TC-053.5."""
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()

    async def fake_get(url, params=None, max_redirects=0):
        return _response(200, "ok")  # looks accepted...

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        return _response(200, json.dumps({"error": "invalid credentials"}))  # ...but re-login fails (no token)

    context.request.get = AsyncMock(side_effect=fake_get)
    context.request.post = AsyncMock(side_effect=fake_post)
    pool = _pool_with_context(context)
    config = AuthTestConfig(
        change_password_url="https://x/rest/user/change-password", test_role="normal",
        test_current_password="oldpw", short_passwords=("abc12",), allow_state_changing_probes=True,
        login_json_endpoint="https://x/rest/user/login", test_username="normal@x.com",
    )
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-025.1"].status == PASS
    assert by_id["TC-025.1"].finding is None


@pytest.mark.asyncio
async def test_weak_password_rejected_passes_without_reverting(tmp_path):
    """Every change-password attempt (from TC-025.1/.2/.3/.4/.5 and
    TC-027.4, which all share this one endpoint) is rejected -- none
    of them should ever report FAIL, and no attempted candidate value
    should show up as an accepted `new` password anywhere in the
    recorded calls."""
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    change_calls: list[dict] = []

    async def fake_get(url, params=None, max_redirects=0):
        if params is not None:
            change_calls.append(params)
        return _response(400, "policy violation")

    context.request.get = AsyncMock(side_effect=fake_get)
    context.request.post = AsyncMock(return_value=_response(400, "policy violation"))
    pool = _pool_with_context(context)
    config = AuthTestConfig(
        change_password_url="https://x/rest/user/change-password", test_role="normal",
        test_current_password="oldpw", short_passwords=("abc12",), allow_state_changing_probes=True,
    )
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    for tid in ("TC-025.1", "TC-025.2", "TC-025.3", "TC-025.4", "TC-027.4"):
        assert by_id[tid].status == PASS, f"{tid} should PASS when every change-password attempt is rejected"
    assert len(change_calls) > 0  # confirms the probes actually ran against the shared endpoint


@pytest.mark.asyncio
async def test_revert_failure_is_logged_as_error_not_swallowed_silently(tmp_path, caplog):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    call_count = {"n": 0}

    async def fake_get(url, params=None, max_redirects=0):
        call_count["n"] += 1
        # First call (set weak password) succeeds; revert call fails.
        return _response(200 if call_count["n"] == 1 else 500, "x")

    context.request.get = AsyncMock(side_effect=fake_get)
    context.request.post = AsyncMock(return_value=_response(500, "x"))
    pool = _pool_with_context(context)
    config = AuthTestConfig(
        change_password_url="https://x/rest/user/change-password", test_role="normal",
        test_current_password="oldpw", short_passwords=("abc12",), allow_state_changing_probes=True,
    )
    module = AuthTestsModule(config=config)

    import logging
    with caplog.at_level(logging.ERROR):
        results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-025.1"].status == FAIL
    assert any("COULD NOT REVERT" in record.message for record in caplog.records)


# ---------------------------------------------------------------------------
# TC-027 Weak Password Reset
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reset_enumeration_fails_when_responses_differ(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        payload = json.loads(data)
        if payload["email"] == "victim@x.com":
            return _response(200, '{"question": "What is your pet\'s name?"}')
        return _response(404, '{"error": "not found"}')

    context.request.post = AsyncMock(side_effect=fake_post)
    pool = _pool_with_context(context)
    config = AuthTestConfig(reset_password_request_url="https://x/rest/user/reset-password", victim_email="victim@x.com")
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-027.5"].status == FAIL


@pytest.mark.asyncio
async def test_reset_enumeration_passes_when_responses_identical(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(200, '{"ok": true}'))
    pool = _pool_with_context(context)
    config = AuthTestConfig(reset_password_request_url="https://x/rest/user/reset-password", victim_email="victim@x.com")
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-027.5"].status == PASS


@pytest.mark.asyncio
async def test_reset_enumeration_skipped_when_unconfigured(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig())

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-027.5"].status == SKIPPED


@pytest.mark.asyncio
async def test_027_3_stays_not_implemented_no_real_inbox_access():
    module = AuthTestsModule(config=AuthTestConfig())
    result = await module._technique_token_referer_leak()
    assert result.status == NOT_IMPLEMENTED


@pytest.mark.asyncio
async def test_027_1_2_6_skip_cleanly_when_unconfigured(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig())

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-027.1"].status == SKIPPED
    assert by_id["TC-027.2"].status == SKIPPED
    assert by_id["TC-027.6"].status == SKIPPED


@pytest.mark.asyncio
async def test_027_1_token_predictable_skips_when_response_does_not_echo_a_token(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(200, '{"ok": true}'))
    pool = _pool_with_context(context)
    config = AuthTestConfig(reset_password_request_url="https://x/rest/user/reset-password", victim_email="victim@x.com")
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-027.1"].status == SKIPPED
    assert "doesn't echo" in by_id["TC-027.1"].detail


@pytest.mark.asyncio
async def test_027_1_token_predictable_fails_on_identical_tokens(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(200, '{"token": "111111"}'))
    pool = _pool_with_context(context)
    config = AuthTestConfig(reset_password_request_url="https://x/rest/user/reset-password", victim_email="victim@x.com")
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-027.1"].status == FAIL


@pytest.mark.asyncio
async def test_027_6_host_header_injection_fails_when_response_reflects_injected_host(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        host = (headers or {}).get("X-Forwarded-Host", "")
        return _response(200, json.dumps({"resetUrl": f"https://{host}/reset?token=abc"}))

    context.request.post = AsyncMock(side_effect=fake_post)
    pool = _pool_with_context(context)
    config = AuthTestConfig(reset_password_request_url="https://x/rest/user/reset-password", victim_email="victim@x.com")
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-027.6"].status == FAIL


def test_config_defaults():
    config = AuthTestConfig()
    assert config.allow_state_changing_probes is False
    assert len(config.credential_pairs) > 0


# ---------------------------------------------------------------------------
# Batch 3 regression: a transient network error during a credential probe
# must surface as ERROR, never a false PASS ("none of N pairs accepted") --
# the same class of bug already fixed for idor_tests.py's
# `_authenticated_context` (see test_idor_tests.py's own transient-error
# regression tests), applied here to `_try_json_login`. Must also not
# abort the other techniques in the same run() -- `_safe_result` isolates
# per-technique failures, mirroring `idor_tests.py`'s per-test try/except.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_default_credentials_reports_error_not_false_pass_on_transient_network_error(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()
    context.request.post = AsyncMock(side_effect=RuntimeError("net::ERR_NETWORK_CHANGED at https://x/rest/user/login"))
    context.request.get = AsyncMock(return_value=_response(200, "a generic homepage"))
    pool = _pool_with_context(context)
    config = AuthTestConfig(login_json_endpoint="https://x/rest/user/login", credential_pairs=(("admin", "admin"),))
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-022.1"].status == ERROR
    assert by_id["TC-022.1"].status != PASS
    # The transient failure in TC-022.1 must not abort the rest of the
    # module's techniques -- every other technique_id still ran (as
    # SKIPPED, since nothing else is configured for this target).
    assert by_id["TC-022.4"].status == SKIPPED
    assert by_id["TC-025.1"].status == SKIPPED


# ---------------------------------------------------------------------------
# Batch 1 — discovered-HTML-login-form fallback (TC-022.1 / TC-027.5 / TC-129.3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_default_credentials_falls_back_to_discovered_html_form_and_fails(tmp_path):
    """TC-022.1 with no `login_json_endpoint` configured, but a real HTML
    login form among the discovered endpoints -- should run against that
    form (via `find_login_endpoint`) instead of SKIPping."""
    login_endpoint = Endpoint(
        url="https://x/doLogin", method="POST", endpoint_type="form",
        parameters=["uid", "passw"], param_locations={"uid": "body", "passw": "body"},
    )
    session_manager = _session_manager(tmp_path, {})

    def fake_post(url, form=None, max_redirects=0):
        if (form or {}).get("uid") == "admin" and (form or {}).get("passw") == "admin":
            return _response(302, "", headers={"location": "/main.jsp"})
        return _response(200, "Invalid username or password")

    context = AsyncMock()
    context.request.post = AsyncMock(side_effect=fake_post)
    pool = _pool_with_context(context)
    config = AuthTestConfig(credential_pairs=(("admin", "admin"),))  # no login_json_endpoint configured
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([login_endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-022.1"].status == FAIL
    assert by_id["TC-022.1"].finding is not None
    assert "doLogin" in by_id["TC-022.1"].finding.request_raw


@pytest.mark.asyncio
async def test_default_credentials_falls_back_to_discovered_html_form_and_passes(tmp_path):
    login_endpoint = Endpoint(
        url="https://x/doLogin", method="POST", endpoint_type="form",
        parameters=["uid", "passw"], param_locations={"uid": "body", "passw": "body"},
    )
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(200, "Invalid username or password"))
    pool = _pool_with_context(context)
    config = AuthTestConfig(credential_pairs=(("admin", "admin"),))
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([login_endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-022.1"].status == PASS


@pytest.mark.asyncio
async def test_default_credentials_still_skips_when_no_json_endpoint_and_no_discovered_form(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig())

    page_endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    results = await module.run_techniques([page_endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-022.1"].status == SKIPPED


@pytest.mark.asyncio
async def test_reset_enumeration_falls_back_to_discovered_html_form_and_fails(tmp_path):
    """TC-027.5 with no `reset_password_request_url` configured, but a
    discovered HTML login form -- should run the same differential test
    against that form instead of SKIPping."""
    login_endpoint = Endpoint(
        url="https://x/doLogin", method="POST", endpoint_type="form",
        parameters=["uid", "passw"], param_locations={"uid": "body", "passw": "body"},
    )
    session_manager = _session_manager(tmp_path, {})

    def fake_post(url, form=None, max_redirects=0):
        if (form or {}).get("uid") == "victim@x.com":
            return _response(200, "Invalid password")
        return _response(404, "No such user")

    context = AsyncMock()
    context.request.post = AsyncMock(side_effect=fake_post)
    pool = _pool_with_context(context)
    config = AuthTestConfig(victim_email="victim@x.com")  # no reset_password_request_url configured
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([login_endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-027.5"].status == FAIL
    assert by_id["TC-027.5"].finding is not None
    assert "doLogin" in by_id["TC-027.5"].finding.request_raw


@pytest.mark.asyncio
async def test_reset_enumeration_still_skips_when_no_url_and_no_discovered_form(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(victim_email="victim@x.com"))

    page_endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    results = await module.run_techniques([page_endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-027.5"].status == SKIPPED


# ---------------------------------------------------------------------------
# TC-022.5 — login-endpoint username enumeration (new)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_022_5_skipped_when_no_test_username_configured(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(login_json_endpoint="https://x/rest/login"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-022.5"].status == SKIPPED
    assert "test_username" in by_id["TC-022.5"].detail


@pytest.mark.asyncio
async def test_022_5_skipped_when_no_login_endpoint_configured_or_discovered(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = AuthTestsModule(config=AuthTestConfig(test_username="realuser@x.com"))

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-022.5"].status == SKIPPED


@pytest.mark.asyncio
async def test_022_5_fails_on_genuine_body_differential_via_json_endpoint(tmp_path):
    session_manager = _session_manager(tmp_path, {})

    async def fake_post(url, data=None, headers=None):
        payload = json.loads(data)
        if payload["username"] == "realuser@x.com":
            return _response(401, '{"error": "invalid password"}')
        return _response(401, '{"error": "no such user"}')

    context = AsyncMock()
    context.request.post = AsyncMock(side_effect=fake_post)
    pool = _pool_with_context(context)
    config = AuthTestConfig(login_json_endpoint="https://x/rest/login", test_username="realuser@x.com")
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-022.5"].status == FAIL
    assert by_id["TC-022.5"].finding is not None
    assert "body length" in by_id["TC-022.5"].finding.description
    # Regression: the finding's own description says this "does not
    # confirm any specific credential as valid" -- a behavioral
    # differential signal, not a confirmed enumerated username.
    assert by_id["TC-022.5"].finding.confidence == "likely"


@pytest.mark.asyncio
async def test_022_5_passes_when_responses_indistinguishable_via_json_endpoint(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(401, '{"error": "invalid credentials"}'))
    pool = _pool_with_context(context)
    config = AuthTestConfig(login_json_endpoint="https://x/rest/login", test_username="realuser@x.com")
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-022.5"].status == PASS


@pytest.mark.asyncio
async def test_022_5_falls_back_to_discovered_html_form_and_fails_on_status_differential(tmp_path):
    login_endpoint = Endpoint(
        url="https://x/doLogin", method="POST", endpoint_type="form",
        parameters=["uid", "passw"], param_locations={"uid": "body", "passw": "body"},
    )
    session_manager = _session_manager(tmp_path, {})

    def fake_post(url, form=None, max_redirects=0):
        if (form or {}).get("uid") == "realuser@x.com":
            return _response(401, "Invalid password")
        return _response(404, "No such user")

    context = AsyncMock()
    context.request.post = AsyncMock(side_effect=fake_post)
    pool = _pool_with_context(context)
    config = AuthTestConfig(test_username="realuser@x.com")  # no login_json_endpoint configured
    module = AuthTestsModule(config=config)

    results = await module.run_techniques([login_endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-022.5"].status == FAIL
    assert "HTTP status differs" in by_id["TC-022.5"].finding.description


# ---------------------------------------------------------------------------
# TC-027.7 -- horizontal account takeover via password-change target-user id
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_horizontal_password_change_skipped_by_default(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(AsyncMock())
    config = AuthTestConfig(
        change_password_url="https://x/rest/user/change-password", test_role="normal",
        test_current_password="oldpw", victim_email="victim@x.com", victim_current_password="victimoldpw",
    )  # allow_state_changing_probes defaults False
    module = AuthTestsModule(config=config)

    result = await module._technique_horizontal_password_change(session_manager, pool, None)

    assert result.status == SKIPPED
    assert "disabled by default" in result.detail


@pytest.mark.asyncio
async def test_horizontal_password_change_skipped_without_victim_config(tmp_path):
    """Requires a SECOND, fully STOF-controlled test account (its own
    known current password) before running at all -- otherwise a
    successful bypass could not be safely reverted."""
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(AsyncMock())
    config = AuthTestConfig(
        change_password_url="https://x/rest/user/change-password", test_role="normal",
        test_current_password="oldpw", allow_state_changing_probes=True,
        # victim_email / victim_current_password deliberately NOT set
    )
    module = AuthTestsModule(config=config)

    result = await module._technique_horizontal_password_change(session_manager, pool, None)

    assert result.status == SKIPPED
    assert "victim_email" in result.detail


@pytest.mark.asyncio
async def test_horizontal_password_change_fails_and_reverts_when_a_target_field_redirects_the_change(tmp_path):
    """The core positive case: a session authenticated as 'normal'
    supplies its OWN valid current password, plus a 'userId' field
    naming a different account -- the server applies the change to
    THAT account instead. Must revert the victim account's password
    back to its original value afterward."""
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    calls: list[dict] = []

    async def fake_get(url, params=None, max_redirects=0):
        calls.append(dict(params or {}))
        # Only the "userId" candidate (first field tried) actually works.
        if params and params.get("userId") == "victim@x.com":
            return _response(200, "ok")
        return _response(400, "rejected")

    context.request.get = AsyncMock(side_effect=fake_get)
    context.request.post = AsyncMock(return_value=_response(400, "rejected"))
    pool = _pool_with_context(context)
    config = AuthTestConfig(
        change_password_url="https://x/rest/user/change-password", test_role="normal",
        test_current_password="oldpw", allow_state_changing_probes=True,
        victim_email="victim@x.com", victim_current_password="victimoldpw",
    )
    module = AuthTestsModule(config=config)

    result = await module._technique_horizontal_password_change(session_manager, pool, None)

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.severity == "High"  # cvss_score=8.8 -- High per the CVSS v3.1 scale (7.0-8.9)
    assert result.finding.vuln_type == "Account Takeover via Unauthorized Password Modification"
    assert "userId" in result.finding.description
    assert "victim@x.com" in result.finding.description
    assert result.finding.confidence == "likely"  # no login_json_endpoint configured to verify the change actually took effect

    userid_calls = [c for c in calls if c.get("userId") == "victim@x.com"]
    assert len(userid_calls) == 2  # set to the probe password, then reverted
    assert userid_calls[0]["new"] == "TargetProbe!3579"
    assert userid_calls[0]["current"] == "oldpw"  # the ATTACKER's own current password, held constant
    assert userid_calls[1]["new"] == "victimoldpw"  # reverted to the victim's real original password


@pytest.mark.asyncio
async def test_horizontal_password_change_confirmed_via_relogin_as_the_victim_account(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()

    async def fake_get(url, params=None, max_redirects=0):
        if params and params.get("userId") == "victim@x.com":
            return _response(200, "ok")
        return _response(400, "rejected")

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        payload = json.loads(data)
        if url == "https://x/rest/user/login":
            if payload.get("email") == "victim@x.com" and payload.get("password") == "TargetProbe!3579":
                return _response(200, json.dumps({"token": "eyFakeJWT"}))
            return _response(200, json.dumps({"error": "invalid credentials"}))
        return _response(400, "rejected")  # targeted change-password POST fallback for other candidate fields

    context.request.get = AsyncMock(side_effect=fake_get)
    context.request.post = AsyncMock(side_effect=fake_post)
    pool = _pool_with_context(context)
    config = AuthTestConfig(
        change_password_url="https://x/rest/user/change-password", test_role="normal",
        test_current_password="oldpw", allow_state_changing_probes=True,
        victim_email="victim@x.com", victim_current_password="victimoldpw",
        login_json_endpoint="https://x/rest/user/login",
    )
    module = AuthTestsModule(config=config)

    result = await module._technique_horizontal_password_change(session_manager, pool, None)

    assert result.status == FAIL
    assert "CONFIRMED" in result.finding.description
    assert result.finding.confidence == "confirmed"


@pytest.mark.asyncio
async def test_horizontal_password_change_downgrades_to_continue_trying_when_relogin_as_victim_fails(tmp_path):
    """HTTP-layer acceptance alone isn't trusted -- if re-login as the
    victim with the probe password fails, that candidate field didn't
    really redirect the change, so the technique must move on to the
    next candidate instead of reporting a false-positive FAIL."""
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()

    async def fake_get(url, params=None, max_redirects=0):
        return _response(200, "ok")  # every candidate field "looks" accepted...

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        return _response(200, json.dumps({"error": "invalid credentials"}))  # ...but re-login as victim always fails

    context.request.get = AsyncMock(side_effect=fake_get)
    context.request.post = AsyncMock(side_effect=fake_post)
    pool = _pool_with_context(context)
    config = AuthTestConfig(
        change_password_url="https://x/rest/user/change-password", test_role="normal",
        test_current_password="oldpw", allow_state_changing_probes=True,
        victim_email="victim@x.com", victim_current_password="victimoldpw",
        login_json_endpoint="https://x/rest/user/login",
    )
    module = AuthTestsModule(config=config)

    result = await module._technique_horizontal_password_change(session_manager, pool, None)

    assert result.status == PASS
    assert result.finding is None


@pytest.mark.asyncio
async def test_horizontal_password_change_passes_when_server_rejects_every_candidate(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    context.request.get = AsyncMock(return_value=_response(400, "rejected"))
    context.request.post = AsyncMock(return_value=_response(400, "rejected"))
    pool = _pool_with_context(context)
    config = AuthTestConfig(
        change_password_url="https://x/rest/user/change-password", test_role="normal",
        test_current_password="oldpw", allow_state_changing_probes=True,
        victim_email="victim@x.com", victim_current_password="victimoldpw",
    )
    module = AuthTestsModule(config=config)

    result = await module._technique_horizontal_password_change(session_manager, pool, None)

    assert result.status == PASS
    assert result.finding is None
    assert "userId" in result.detail  # names the candidates it actually tried


@pytest.mark.asyncio
async def test_horizontal_password_change_revert_failure_is_logged_as_error(tmp_path, caplog):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    call_count = {"n": 0}

    async def fake_get(url, params=None, max_redirects=0):
        if params and params.get("userId") == "victim@x.com":
            call_count["n"] += 1
            # First call (set the probe password) succeeds; the revert call fails.
            return _response(200 if call_count["n"] == 1 else 500, "x")
        return _response(400, "rejected")

    context.request.get = AsyncMock(side_effect=fake_get)
    context.request.post = AsyncMock(return_value=_response(500, "x"))
    pool = _pool_with_context(context)
    config = AuthTestConfig(
        change_password_url="https://x/rest/user/change-password", test_role="normal",
        test_current_password="oldpw", allow_state_changing_probes=True,
        victim_email="victim@x.com", victim_current_password="victimoldpw",
    )
    module = AuthTestsModule(config=config)

    import logging
    with caplog.at_level(logging.ERROR):
        result = await module._technique_horizontal_password_change(session_manager, pool, None)

    assert result.status == FAIL
    assert any("COULD NOT REVERT" in rec.message for rec in caplog.records)
