"""Unit tests for Layer 9 — stof.modules.sqli_tests (TC-127)."""
from unittest.mock import AsyncMock, patch

import pytest

from stof.auth.base import AuthProvider
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.results import ERROR, FAIL, PASS, SKIPPED
from stof.modules.sqli_tests import (
    SqliTestConfig,
    SqliTestsModule,
    controllable_cookie_names,
    find_login_endpoint,
    looks_authenticated,
    looks_like_sql_error,
)
from stof.session.models import Session
from stof.session.session_manager import SessionManager
from stof.session.session_store import SessionStore

# ---------------------------------------------------------------------------
# Pure functions
# ---------------------------------------------------------------------------


def test_looks_like_sql_error_matches_known_fingerprint():
    assert looks_like_sql_error("You have an error in your SQL syntax near '1'") == "sql syntax"


def test_looks_like_sql_error_none_for_ordinary_page():
    assert looks_like_sql_error("<html>Welcome to the site</html>") is None


def test_find_login_endpoint_matches_username_and_password_fields():
    endpoints = [
        Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"]),
        Endpoint(url="https://x/doLogin", method="POST", endpoint_type="form", parameters=["uid", "passw"]),
    ]
    found = find_login_endpoint(endpoints)
    assert found is not None
    assert found.url == "https://x/doLogin"


def test_find_login_endpoint_none_when_no_form_has_both_fields():
    endpoints = [Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])]
    assert find_login_endpoint(endpoints) is None


def test_find_login_endpoint_prefers_form_type_over_api_type():
    api_guess = Endpoint(url="https://x/api/session", method="POST", endpoint_type="api", parameters=["username", "password"])
    real_form = Endpoint(url="https://x/doLogin", method="POST", endpoint_type="form", parameters=["uid", "passw"])
    found = find_login_endpoint([api_guess, real_form])
    assert found.url == "https://x/doLogin"


def test_looks_authenticated_true_on_redirect_away_from_login():
    assert looks_authenticated(
        302, {"location": "/main.jsp"}, "", 200, {}, "login failed, please try again",
    )


def test_looks_authenticated_true_on_new_success_marker():
    assert looks_authenticated(
        200, {}, "Welcome back! <a href='/logout'>logout</a>", 200, {}, "Invalid username or password",
    )


def test_looks_authenticated_false_when_both_responses_look_the_same():
    assert not looks_authenticated(200, {}, "Invalid credentials", 200, {}, "Invalid credentials")


def test_looks_authenticated_false_on_redirect_back_to_login():
    assert not looks_authenticated(
        302, {"location": "/login.jsp?error=1"}, "", 302, {"location": "/login.jsp?error=1"}, "",
    )


# ---------------------------------------------------------------------------
# looks_authenticated -- JSON API login responses (a modern SPA backend,
# e.g. this project's own Juice Shop benchmark, never redirects or
# returns HTML on login; it returns a JSON body carrying a token).
# ---------------------------------------------------------------------------


def test_looks_authenticated_true_on_json_body_carrying_a_token():
    assert looks_authenticated(
        200, {}, '{"authentication":{"token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.abc.def","bid":1}}',
        200, {}, '{"error":{"message":"Invalid email or password."}}',
    )


def test_looks_authenticated_false_when_both_json_responses_are_errors():
    assert not looks_authenticated(
        200, {}, '{"error":{"message":"Invalid email or password."}}',
        200, {}, '{"error":{"message":"Invalid email or password."}}',
    )


def test_looks_authenticated_false_on_json_body_with_no_token_shaped_field():
    assert not looks_authenticated(
        200, {}, '{"status":"ok","items":[]}',
        200, {}, '{"error":"nope"}',
    )


def test_looks_authenticated_false_when_baseline_already_carries_a_token():
    """A baseline response that itself carries a token-shaped field
    (an endpoint that always issues some token regardless of validity)
    must not make every later probe look like a false success."""
    assert not looks_authenticated(
        200, {}, '{"token":"same-token-value-both-times"}',
        200, {}, '{"token":"same-token-value-both-times"}',
    )


def test_controllable_cookie_names_excludes_session_and_auth_shaped_cookies():
    cookies = {"JSESSIONID": "abc123", "cart_currency": "USD", "csrftoken": "xyz", "lang": "en"}
    assert sorted(controllable_cookie_names(cookies)) == ["cart_currency", "lang"]


def test_controllable_cookie_names_empty_when_only_auth_cookies_present():
    assert controllable_cookie_names({"JSESSIONID": "abc123", "auth_token": "xyz"}) == []


def test_controllable_cookie_names_empty_for_no_cookies():
    assert controllable_cookie_names({}) == []


# ---------------------------------------------------------------------------
# run_techniques() — async
# ---------------------------------------------------------------------------


def _user(role: str) -> UserConfig:
    return UserConfig(id=f"{role}-01", role=role, username=role, password="pw", auth_type="form_login")


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


def _fake_context(get_side_effect=None, post_side_effect=None):
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=AsyncMock())
    if get_side_effect is not None:
        context.request.get = AsyncMock(side_effect=get_side_effect)
    if post_side_effect is not None:
        context.request.post = AsyncMock(side_effect=post_side_effect)
    return context


def _pool_with_context(context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


def _by_id(results):
    return {r.technique_id: r for r in results}


@pytest.mark.asyncio
async def test_run_techniques_skipped_when_no_injectable_endpoints(tmp_path):
    """No endpoints discovered at all -- every technique should report
    SKIPPED, not silently do nothing."""
    endpoints: list[Endpoint] = []
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = SqliTestsModule()

    results = await module.run_techniques(endpoints, session_manager, pool)

    by_id = _by_id(results)
    assert len(by_id) == 8
    assert all(r.status == SKIPPED for r in by_id.values())


@pytest.mark.asyncio
async def test_error_based_fails_on_db_error_fingerprint(tmp_path):
    """A payload that isn't the benign baseline value triggers a
    SQL-error-shaped response -- TC-127.1 should FAIL with evidence,
    while the other techniques (which see the same mock but a
    different signal shape) correctly stay clean."""
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    def fake_get(url, params=None, max_redirects=0):
        q = (params or {}).get("q", "")
        if q == "stof-probe":  # the benign placeholder value -- see _injection_shared.placeholder_value
            return _response(200, "normal search results page")
        return _response(200, "You have an error in your SQL syntax near '1'")

    pool = _pool_with_context(_fake_context(get_side_effect=fake_get))
    module = SqliTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = _by_id(results)
    assert by_id["TC-127.1"].status == FAIL
    assert by_id["TC-127.1"].finding is not None
    assert "sql syntax" in by_id["TC-127.1"].finding.description.lower()
    # No union-based data pull / claim of extracted data anywhere in the description.
    assert "extract" not in by_id["TC-127.1"].finding.description.lower() or "no data was" in by_id["TC-127.1"].finding.description.lower()


@pytest.mark.asyncio
async def test_all_role_based_techniques_pass_on_a_clean_target(tmp_path):
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    def fake_get(url, params=None, max_redirects=0):
        return _response(200, "normal search results page, always identical")

    pool = _pool_with_context(_fake_context(get_side_effect=fake_get))
    module = SqliTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = _by_id(results)
    assert by_id["TC-127.1"].status == PASS
    assert by_id["TC-127.2"].status == PASS
    assert by_id["TC-127.3"].status == PASS


@pytest.mark.asyncio
async def test_role_not_configured_skips_the_three_role_based_techniques(tmp_path):
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="u", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = SqliTestsModule()  # default low_priv_role="normal", not configured above

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = _by_id(results)
    assert by_id["TC-127.1"].status == SKIPPED
    assert by_id["TC-127.2"].status == SKIPPED
    assert by_id["TC-127.3"].status == SKIPPED
    assert "not configured" in by_id["TC-127.1"].detail


# ---------------------------------------------------------------------------
# TC-127.2 boolean-based blind — technique-level (bypasses run_techniques
# so the true/false payload strings can be read back from the module
# itself rather than duplicated as literals in this test file)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_boolean_blind_fails_on_true_false_differential():
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    module = SqliTestsModule()
    true_payload, false_payload = module._boolean_blind_payloads()
    catalog_page = "Product A, Product B, Product C -- catalog footer nav header"
    empty_page = "No results found -- footer nav header"

    def fake_get(url, params=None, max_redirects=0):
        q = (params or {}).get("q", "")
        if q == false_payload:
            return _response(200, empty_page)
        return _response(200, catalog_page)  # baseline and true-payload both look like a normal listing

    context = _fake_context(get_side_effect=fake_get)
    candidates = [(endpoint, "q", "query")]

    result = await module._technique_boolean_blind(candidates, context, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert true_payload in result.finding.request_raw


@pytest.mark.asyncio
async def test_boolean_blind_passes_when_true_and_false_look_the_same():
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    module = SqliTestsModule()

    def fake_get(url, params=None, max_redirects=0):
        return _response(200, "identical page every time")

    context = _fake_context(get_side_effect=fake_get)
    candidates = [(endpoint, "q", "query")]

    result = await module._technique_boolean_blind(candidates, context, evidence=None)

    assert result.status == PASS


# ---------------------------------------------------------------------------
# TC-127.3 time-based blind — technique-level, with `time.monotonic()`
# patched so a "repeatable multi-second delay" is simulated instantly
# instead of the test actually sleeping for several seconds.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_time_based_fails_on_a_repeatable_delay():
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    module = SqliTestsModule()

    def fake_get(url, params=None, max_redirects=0):
        return _response(200, "ok")

    context = _fake_context(get_side_effect=fake_get)
    candidates = [(endpoint, "q", "query")]

    # 2 send_probe() calls per _time_based_candidate() invocation (baseline,
    # payload), each reading time.monotonic() twice (start, elapsed) -- 4
    # readings per invocation, x2 invocations (first attempt + confirm).
    timestamps = iter([0.0, 0.1, 0.2, 2.3, 2.4, 2.5, 2.6, 4.8])
    with patch("stof.modules._injection_shared.time.monotonic", side_effect=lambda: next(timestamps)):
        result = await module._technique_time_based(candidates, context, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None


@pytest.mark.asyncio
async def test_time_based_passes_when_delay_does_not_repeat():
    """A one-off slow response (network jitter) must NOT be reported --
    the delay has to repeat on the confirmation probe."""
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    module = SqliTestsModule()

    def fake_get(url, params=None, max_redirects=0):
        return _response(200, "ok")

    context = _fake_context(get_side_effect=fake_get)
    candidates = [(endpoint, "q", "query")]

    # First attempt looks like a hit (delta 2.0s); confirmation attempt
    # does not (delta 0.1s) -- must not be reported as FAIL.
    timestamps = iter([0.0, 0.1, 0.2, 2.3, 2.4, 2.5, 2.6, 2.7])
    with patch("stof.modules._injection_shared.time.monotonic", side_effect=lambda: next(timestamps)):
        result = await module._technique_time_based(candidates, context, evidence=None)

    assert result.status == PASS


# ---------------------------------------------------------------------------
# TC-127.4 login bypass
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_bypass_fails_on_authenticated_looking_response(tmp_path):
    login_endpoint = Endpoint(url="https://x/doLogin", method="POST", endpoint_type="form", parameters=["uid", "passw"], param_locations={"uid": "body", "passw": "body"})
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    def fake_post(url, form=None, max_redirects=0):
        if (form or {}).get("uid") == "stof-nonexistent-user":
            return _response(200, "Invalid username or password")
        return _response(302, "", headers={"location": "/main.jsp"})

    pool = _pool_with_context(_fake_context(post_side_effect=fake_post))
    module = SqliTestsModule()

    results = await module.run_techniques([login_endpoint], session_manager, pool)

    by_id = _by_id(results)
    assert by_id["TC-127.4"].status == FAIL
    assert by_id["TC-127.4"].finding is not None
    assert by_id["TC-127.4"].finding.severity == "Critical"


@pytest.mark.asyncio
async def test_login_bypass_passes_when_every_payload_rejected(tmp_path):
    login_endpoint = Endpoint(url="https://x/doLogin", method="POST", endpoint_type="form", parameters=["uid", "passw"], param_locations={"uid": "body", "passw": "body"})
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    def fake_post(url, form=None, max_redirects=0):
        return _response(200, "Invalid username or password")

    pool = _pool_with_context(_fake_context(post_side_effect=fake_post))
    module = SqliTestsModule()

    results = await module.run_techniques([login_endpoint], session_manager, pool)

    assert _by_id(results)["TC-127.4"].status == PASS


@pytest.mark.asyncio
async def test_login_bypass_skipped_when_no_login_form_discovered(tmp_path):
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = SqliTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    assert _by_id(results)["TC-127.4"].status == SKIPPED


@pytest.mark.asyncio
async def test_login_bypass_errors_when_baseline_probe_fails(tmp_path):
    login_endpoint = Endpoint(url="https://x/doLogin", method="POST", endpoint_type="form", parameters=["uid", "passw"], param_locations={"uid": "body", "passw": "body"})
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    def fake_post(url, form=None, max_redirects=0):
        raise RuntimeError("connection reset")

    pool = _pool_with_context(_fake_context(post_side_effect=fake_post))
    module = SqliTestsModule()

    results = await module.run_techniques([login_endpoint], session_manager, pool)

    assert _by_id(results)["TC-127.4"].status == ERROR


# ---------------------------------------------------------------------------
# TC-127.5 header-based
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_header_based_fails_on_db_error_fingerprint():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    module = SqliTestsModule()

    def fake_get(url, params=None, max_redirects=0, headers=None):
        if headers and "User-Agent" in headers:
            return _response(200, "You have an error in your SQL syntax near '1'")
        return _response(200, "normal page")

    context = _fake_context(get_side_effect=fake_get)

    result = await module._technique_header_based([endpoint], context, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert "User-Agent" in result.finding.description
    assert "sql syntax" in result.finding.description.lower()


@pytest.mark.asyncio
async def test_header_based_passes_on_a_clean_target():
    endpoint = Endpoint(url="https://x/", method="GET", endpoint_type="page")
    module = SqliTestsModule()

    def fake_get(url, params=None, max_redirects=0, headers=None):
        return _response(200, "normal page every time")

    context = _fake_context(get_side_effect=fake_get)

    result = await module._technique_header_based([endpoint], context, evidence=None)

    assert result.status == PASS


@pytest.mark.asyncio
async def test_header_based_skipped_when_no_endpoints():
    module = SqliTestsModule()
    result = await module._technique_header_based([], context=None, evidence=None)
    assert result.status == SKIPPED


# ---------------------------------------------------------------------------
# TC-127.6 second-order (plant/verify)
# ---------------------------------------------------------------------------


def _second_order_endpoints():
    plant = Endpoint(
        url="https://x/sendFeedback", method="POST", endpoint_type="form",
        parameters=["name", "email_addr", "subject", "comments"],
        param_locations={"name": "body", "email_addr": "body", "subject": "body", "comments": "body"},
    )
    verify = Endpoint(url="https://x/admin/admin.jsp", method="GET", endpoint_type="page")
    return [plant, verify]


@pytest.mark.asyncio
async def test_second_order_fails_when_plant_and_verify_both_succeed(tmp_path):
    endpoints = _second_order_endpoints()
    session_manager = _session_manager(tmp_path, {
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
    })

    def fake_post(url, form=None, max_redirects=0):
        return _response(200, "Thank you for your feedback")

    def fake_get(url, max_redirects=0):
        if "admin" in url:
            return _response(200, "You have an error in your SQL syntax near '1'")
        return _response(200, "ok")

    context = _fake_context(get_side_effect=fake_get, post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = SqliTestsModule(config=SqliTestConfig(allow_state_changing_probes=True))

    result = await module._technique_second_order(endpoints, session_manager, pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert "sendFeedback" in result.finding.description
    assert "admin.jsp" in result.finding.description
    assert "sql syntax" in result.finding.description.lower()


@pytest.mark.asyncio
async def test_second_order_passes_when_verify_finds_nothing(tmp_path):
    endpoints = _second_order_endpoints()
    session_manager = _session_manager(tmp_path, {
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
    })

    def fake_post(url, form=None, max_redirects=0):
        return _response(200, "Thank you for your feedback")

    def fake_get(url, max_redirects=0):
        return _response(200, "clean admin review page")

    context = _fake_context(get_side_effect=fake_get, post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = SqliTestsModule(config=SqliTestConfig(allow_state_changing_probes=True))

    result = await module._technique_second_order(endpoints, session_manager, pool, evidence=None)

    assert result.status == PASS


@pytest.mark.asyncio
async def test_second_order_skipped_when_state_changing_probes_disabled(tmp_path):
    endpoints = _second_order_endpoints()
    session_manager = _session_manager(tmp_path, {
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
    })
    pool = _pool_with_context(_fake_context())
    module = SqliTestsModule()  # allow_state_changing_probes defaults False

    result = await module._technique_second_order(endpoints, session_manager, pool, evidence=None)

    assert result.status == SKIPPED
    assert "allow_state_changing_probes" in result.detail


@pytest.mark.asyncio
async def test_second_order_skipped_when_no_free_text_field_discovered(tmp_path):
    endpoints = [Endpoint(url="https://x/admin/admin.jsp", method="GET", endpoint_type="page")]
    session_manager = _session_manager(tmp_path, {
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
    })
    pool = _pool_with_context(_fake_context())
    module = SqliTestsModule(config=SqliTestConfig(allow_state_changing_probes=True))

    result = await module._technique_second_order(endpoints, session_manager, pool, evidence=None)

    assert result.status == SKIPPED


# ---------------------------------------------------------------------------
# TC-127.7 JSON-body
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_json_body_fails_on_db_error_fingerprint():
    endpoint = Endpoint(url="https://x/api/search", method="POST", endpoint_type="api", parameters=["q"], param_locations={"q": "body"})
    module = SqliTestsModule()

    def fake_post(url, data=None, max_redirects=0, headers=None):
        assert headers is not None and headers.get("Content-Type") == "application/json"
        if '"stof-probe"' in data:
            return _response(200, "normal results")
        return _response(200, "You have an error in your SQL syntax near '1'")

    context = _fake_context(post_side_effect=fake_post)

    result = await module._technique_json_body([endpoint], context, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert "application/json" in result.finding.description
    assert "sql syntax" in result.finding.description.lower()
    assert "extract" not in result.finding.description.lower() or "no data was" in result.finding.description.lower()


@pytest.mark.asyncio
async def test_json_body_passes_on_a_clean_target():
    endpoint = Endpoint(url="https://x/api/search", method="POST", endpoint_type="api", parameters=["q"], param_locations={"q": "body"})
    module = SqliTestsModule()

    def fake_post(url, data=None, max_redirects=0, headers=None):
        return _response(200, "normal results every time")

    context = _fake_context(post_side_effect=fake_post)

    result = await module._technique_json_body([endpoint], context, evidence=None)

    assert result.status == PASS


@pytest.mark.asyncio
async def test_json_body_skipped_when_no_api_endpoint_discovered():
    """Only form/page-shaped endpoints discovered -- this technique
    specifically targets endpoint_type=='api', form-encoded coverage is
    already TC-127.1's job."""
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    module = SqliTestsModule()

    result = await module._technique_json_body([endpoint], context=None, evidence=None)

    assert result.status == SKIPPED


@pytest.mark.asyncio
async def test_json_body_skipped_for_form_encoded_api_endpoint_with_wrong_method():
    """A GET api endpoint isn't a JSON-body candidate (GET has no body
    to carry JSON in) -- must skip, not silently probe it as GET."""
    endpoint = Endpoint(url="https://x/api/items", method="GET", endpoint_type="api", parameters=["id"])
    module = SqliTestsModule()

    result = await module._technique_json_body([endpoint], context=None, evidence=None)

    assert result.status == SKIPPED


# ---------------------------------------------------------------------------
# TC-127.8 cookie-based
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cookie_based_fails_on_db_error_fingerprint():
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    module = SqliTestsModule()
    session = Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "real-session-value", "lang": "en"})

    def fake_get(url, params=None, max_redirects=0, headers=None):
        cookie_header = (headers or {}).get("Cookie", "")
        if "lang=" in cookie_header and "lang=en" not in cookie_header:
            return _response(200, "You have an error in your SQL syntax near '1'")
        return _response(200, "normal page")

    context = _fake_context(get_side_effect=fake_get)

    result = await module._technique_cookie_based([endpoint], session, context, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert "lang" in result.finding.description
    # Never claims to touch the real session cookie.
    assert "JSESSIONID" not in result.finding.description
    assert "sql syntax" in result.finding.description.lower()


@pytest.mark.asyncio
async def test_cookie_based_never_overrides_the_session_cookie_itself():
    """Even on a target that would trip the error fingerprint on any
    cookie value, JSESSIONID must never be the one carrying the
    payload -- only 'lang' (the one non-auth cookie) is tested."""
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    module = SqliTestsModule()
    session = Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "real-session-value", "lang": "en"})
    seen_cookie_headers = []

    def fake_get(url, params=None, max_redirects=0, headers=None):
        cookie_header = (headers or {}).get("Cookie", "")
        seen_cookie_headers.append(cookie_header)
        return _response(200, "normal page")

    context = _fake_context(get_side_effect=fake_get)

    result = await module._technique_cookie_based([endpoint], session, context, evidence=None)

    assert result.status == PASS
    assert seen_cookie_headers  # probes actually happened
    for header in seen_cookie_headers:
        assert "JSESSIONID=real-session-value" in header  # untouched, always the real value


@pytest.mark.asyncio
async def test_cookie_based_skipped_when_only_session_auth_cookies_present():
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    module = SqliTestsModule()
    session = Session(user_id="u", role="normal", auth_type="form_login", cookies={"JSESSIONID": "real-session-value"})

    result = await module._technique_cookie_based([endpoint], session, context=None, evidence=None)

    assert result.status == SKIPPED
    assert "no non-session/auth cookie" in result.detail


@pytest.mark.asyncio
async def test_cookie_based_skipped_when_no_endpoints():
    module = SqliTestsModule()
    session = Session(user_id="u", role="normal", auth_type="form_login", cookies={"lang": "en"})

    result = await module._technique_cookie_based([], session, context=None, evidence=None)

    assert result.status == SKIPPED
