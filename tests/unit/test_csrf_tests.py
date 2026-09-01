"""Unit tests for Layer 9 — stof.modules.csrf_tests (TC-130)."""
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthProvider
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.csrf_tests import (
    CsrfTestConfig,
    CsrfTestsModule,
    _candidate_json_api_endpoints,
    _samesite_csrf_issue,
    find_csrf_token_field,
)
from stof.modules.results import ERROR, FAIL, PASS, SKIPPED
from stof.session.models import Session
from stof.session.session_manager import SessionManager
from stof.session.session_store import SessionStore


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


def _response(status: int, body: str):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    return resp


def _pool_with_context(context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


def _pool_with_contexts(*contexts) -> SessionPool:
    """TC-130.4 needs two DIFFERENT roles' contexts (attacker, then
    victim) -- `SessionPool.get_context()` caches per role and calls
    `browser.new_context()` once per distinct role, in the order those
    roles are first authenticated (attacker first, from
    `run_techniques()`'s own initial `_authenticated_context`; then a
    THIRD, uncached anonymous context for TC-130.5's own
    `session_pool.new_anonymous_context()` cookie diff, run once before
    the per-endpoint loop; victim last, inside the TC-130.4 check) -- so
    a plain ordered `side_effect` list matches that call order exactly."""
    browser = AsyncMock()
    browser.new_context = AsyncMock(side_effect=list(contexts))
    return SessionPool(browser)


def _form_endpoint(url="https://x/bank/addAccount", token=True, token_value="tok-abc123") -> Endpoint:  # noqa: S107 -- fixture data (a fake CSRF token string), not a real credential
    parameters = ["accountType", "amount"]
    parameter_values = {}
    if token:
        parameters = ["csrfmiddlewaretoken", *parameters]
        parameter_values = {"csrfmiddlewaretoken": token_value}
    return Endpoint(
        url=url, method="POST", endpoint_type="form",
        parameters=parameters, param_locations=dict.fromkeys(parameters, "body"),
        parameter_values=parameter_values,
    )


# ---------------------------------------------------------------------------
# find_csrf_token_field — pure function
# ---------------------------------------------------------------------------


def test_find_csrf_token_field_matches_common_names():
    endpoint = Endpoint(url="https://x/f", method="POST", endpoint_type="form", parameters=["csrf_token", "amount"])
    assert find_csrf_token_field(endpoint) == "csrf_token"


def test_find_csrf_token_field_none_when_absent():
    endpoint = Endpoint(url="https://x/f", method="POST", endpoint_type="form", parameters=["amount", "accountType"])
    assert find_csrf_token_field(endpoint) is None


# ---------------------------------------------------------------------------
# run_techniques() — gating / skip conditions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_skipped_when_no_test_role_configured(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = CsrfTestsModule(config=CsrfTestConfig(allow_state_changing_probes=True))

    results = await module.run_techniques([_form_endpoint()], session_manager, pool)

    assert len(results) == 6
    assert all(r.status == SKIPPED for r in results)


@pytest.mark.asyncio
async def test_skipped_when_role_uses_jwt_auth(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(AsyncMock())
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="jwt", allow_state_changing_probes=True))

    results = await module.run_techniques([_form_endpoint()], session_manager, pool)

    assert len(results) == 6
    assert all(r.status == SKIPPED for r in results)
    assert all("jwt" in r.detail for r in results)


@pytest.mark.asyncio
async def test_skipped_when_state_changing_probes_disabled(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(AsyncMock())
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login"))  # allow_state_changing_probes defaults False

    results = await module.run_techniques([_form_endpoint()], session_manager, pool)

    assert len(results) == 6
    assert all(r.status == SKIPPED for r in results)
    assert all("disabled by default" in r.detail for r in results)


@pytest.mark.asyncio
async def test_skipped_when_no_candidate_form_endpoint(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(AsyncMock())
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    get_endpoint = Endpoint(url="https://x/page", method="GET", endpoint_type="page")

    results = await module.run_techniques([get_endpoint], session_manager, pool)

    assert len(results) == 6
    assert all(r.status == SKIPPED for r in results)
    assert all("no discovered state-changing POST form endpoint" in r.detail for r in results)


# ---------------------------------------------------------------------------
# TC-130.1 — missing token field
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_130_1_fails_when_no_token_field_present(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(302, ""))
    pool = _pool_with_context(context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _form_endpoint(token=False)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.1"].status == FAIL
    assert by_id["TC-130.1"].finding is not None


@pytest.mark.asyncio
async def test_130_1_passes_when_token_field_present(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(302, ""))
    pool = _pool_with_context(context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _form_endpoint(token=True)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.1"].status == PASS


# ---------------------------------------------------------------------------
# TC-130.2 — stripped-token replay
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_130_2_skipped_when_no_token_field_to_strip(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(302, ""))
    pool = _pool_with_context(context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _form_endpoint(token=False)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.2"].status == SKIPPED


@pytest.mark.asyncio
async def test_130_2_fails_when_stripped_token_request_still_succeeds(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    # Every submission (baseline AND stripped) succeeds identically --
    # the server never actually checks the token at all.
    context.request.post = AsyncMock(return_value=_response(302, "account created"))
    pool = _pool_with_context(context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _form_endpoint(token=True)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.2"].status == FAIL
    assert by_id["TC-130.2"].finding is not None
    assert "csrfmiddlewaretoken" in by_id["TC-130.2"].finding.description


@pytest.mark.asyncio
async def test_130_2_passes_when_stripped_token_request_is_rejected(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    call_count = {"n": 0}

    async def fake_post(url, form=None, headers=None, max_redirects=0):
        call_count["n"] += 1
        if call_count["n"] == 1:  # baseline (token included) succeeds
            return _response(302, "account created")
        return _response(403, "CSRF token missing or invalid")  # stripped-token retries are rejected

    context.request.post = AsyncMock(side_effect=fake_post)
    pool = _pool_with_context(context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _form_endpoint(token=True)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.2"].status == PASS
    assert by_id["TC-130.3"].status == PASS


@pytest.mark.asyncio
async def test_130_2_and_130_3_error_when_baseline_itself_fails(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    # The baseline (fully-formed, token-included) request itself fails --
    # e.g. a stale crawled token value -- so there's no working ground
    # truth to compare a stripped/spoofed retry against.
    context.request.post = AsyncMock(return_value=_response(403, "CSRF token missing or invalid"))
    pool = _pool_with_context(context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _form_endpoint(token=True)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.2"].status == ERROR
    assert by_id["TC-130.3"].status == ERROR


# ---------------------------------------------------------------------------
# TC-130.3 — spoofed Origin/Referer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_130_3_fails_when_spoofed_origin_request_still_succeeds(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(302, "account created"))
    pool = _pool_with_context(context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _form_endpoint(token=True)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.3"].status == FAIL
    assert by_id["TC-130.3"].finding is not None
    assert "attacker-controlled.invalid" in by_id["TC-130.3"].finding.description

    # Verify the spoofed headers were actually sent on at least one call.
    spoofed_calls = [
        call for call in context.request.post.await_args_list
        if call.kwargs.get("headers", {}).get("Origin") == "https://attacker-controlled.invalid"
    ]
    assert len(spoofed_calls) == 1


@pytest.mark.asyncio
async def test_130_3_passes_when_spoofed_origin_is_rejected(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()

    async def fake_post(url, form=None, headers=None, max_redirects=0):
        origin = (headers or {}).get("Origin")
        if origin == "https://attacker-controlled.invalid":
            return _response(403, "Forbidden -- origin mismatch")
        return _response(302, "account created")

    context.request.post = AsyncMock(side_effect=fake_post)
    pool = _pool_with_context(context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _form_endpoint(token=True)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.3"].status == PASS
    # This mock only rejects on a mismatched Origin -- it never actually
    # validates the token itself, so the stripped-token retry (which
    # carries no Origin header at all) is accepted just like the
    # baseline: a real, distinct finding for TC-130.2, independent of
    # TC-130.3's own origin-validation result.
    assert by_id["TC-130.2"].status == FAIL


# ---------------------------------------------------------------------------
# TC-130.4 — token harvested from a DIFFERENT user's session
# ---------------------------------------------------------------------------

_ATTACKER_TOKEN_HTML = '<input type="hidden" name="csrfmiddlewaretoken" value="attacker-tok-999">'


def _two_role_session_manager(tmp_path):
    return _session_manager(tmp_path, {
        "normal": Session(user_id="u1", role="normal", auth_type="form_login"),
        "admin": Session(user_id="u2", role="admin", auth_type="form_login"),
    })


@pytest.mark.asyncio
async def test_130_4_skipped_when_no_victim_role_configured(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(302, "account created"))
    context.request.get = AsyncMock(return_value=_response(200, _ATTACKER_TOKEN_HTML))
    pool = _pool_with_context(context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _form_endpoint(token=True)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.4"].status == SKIPPED
    assert "victim_role" in by_id["TC-130.4"].detail
    # TC-130.1-.3 are unaffected by TC-130.4's own gating.
    assert by_id["TC-130.1"].status == PASS


@pytest.mark.asyncio
async def test_130_4_skipped_when_victim_role_is_jwt_auth(tmp_path):
    session_manager = _two_role_session_manager(tmp_path)
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(302, "account created"))
    context.request.get = AsyncMock(return_value=_response(200, _ATTACKER_TOKEN_HTML))
    pool = _pool_with_context(context)
    module = CsrfTestsModule(config=CsrfTestConfig(
        test_role="normal", role_auth_type="form_login",
        victim_role="admin", victim_role_auth_type="jwt",
        allow_state_changing_probes=True,
    ))
    endpoint = _form_endpoint(token=True)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.4"].status == SKIPPED
    assert "jwt" in by_id["TC-130.4"].detail


@pytest.mark.asyncio
async def test_130_4_error_when_attacker_token_cannot_be_harvested(tmp_path):
    session_manager = _two_role_session_manager(tmp_path)
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(302, "account created"))
    context.request.get = AsyncMock(side_effect=Exception("net::ERR_CONNECTION_RESET"))
    pool = _pool_with_context(context)
    module = CsrfTestsModule(config=CsrfTestConfig(
        test_role="normal", role_auth_type="form_login",
        victim_role="admin", victim_role_auth_type="form_login",
        allow_state_changing_probes=True,
    ))
    endpoint = _form_endpoint(token=True)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.4"].status == "ERROR"
    assert "harvest" in by_id["TC-130.4"].detail


@pytest.mark.asyncio
async def test_130_4_fails_when_victim_session_accepts_attackers_token(tmp_path):
    session_manager = _two_role_session_manager(tmp_path)
    attacker_context = AsyncMock()
    attacker_context.request.post = AsyncMock(return_value=_response(302, "account created"))
    attacker_context.request.get = AsyncMock(return_value=_response(200, _ATTACKER_TOKEN_HTML))
    victim_context = AsyncMock()
    # Every submission under the victim's own session succeeds --
    # including one carrying the attacker's harvested token -- the
    # server never actually checks whose session issued the token.
    victim_context.request.post = AsyncMock(return_value=_response(302, "account created"))
    pool = _pool_with_contexts(attacker_context, AsyncMock(), victim_context)
    module = CsrfTestsModule(config=CsrfTestConfig(
        test_role="normal", role_auth_type="form_login",
        victim_role="admin", victim_role_auth_type="form_login",
        allow_state_changing_probes=True,
    ))
    endpoint = _form_endpoint(token=True)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.4"].status == FAIL
    assert by_id["TC-130.4"].finding is not None
    assert "attacker-tok-999" in by_id["TC-130.4"].finding.request_raw
    assert "admin" in by_id["TC-130.4"].finding.description
    assert "normal" in by_id["TC-130.4"].finding.description


@pytest.mark.asyncio
async def test_130_4_passes_when_victim_session_rejects_attackers_token(tmp_path):
    session_manager = _two_role_session_manager(tmp_path)
    attacker_context = AsyncMock()
    attacker_context.request.post = AsyncMock(return_value=_response(302, "account created"))
    attacker_context.request.get = AsyncMock(return_value=_response(200, _ATTACKER_TOKEN_HTML))

    async def victim_fake_post(url, form=None, headers=None, max_redirects=0):
        if (form or {}).get("csrfmiddlewaretoken") == "attacker-tok-999":
            return _response(403, "CSRF token missing or invalid")
        return _response(302, "account created")  # victim's own baseline (own crawled token) succeeds

    victim_context = AsyncMock()
    victim_context.request.post = AsyncMock(side_effect=victim_fake_post)
    pool = _pool_with_contexts(attacker_context, AsyncMock(), victim_context)
    module = CsrfTestsModule(config=CsrfTestConfig(
        test_role="normal", role_auth_type="form_login",
        victim_role="admin", victim_role_auth_type="form_login",
        allow_state_changing_probes=True,
    ))
    endpoint = _form_endpoint(token=True)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.4"].status == PASS


@pytest.mark.asyncio
async def test_130_4_error_when_victim_baseline_itself_fails(tmp_path):
    session_manager = _two_role_session_manager(tmp_path)
    attacker_context = AsyncMock()
    attacker_context.request.post = AsyncMock(return_value=_response(302, "account created"))
    attacker_context.request.get = AsyncMock(return_value=_response(200, _ATTACKER_TOKEN_HTML))
    victim_context = AsyncMock()
    # Even the victim's own known-good submission fails -- e.g. a stale
    # crawled token value -- so there's no working ground truth to
    # compare the cross-session substitution against.
    victim_context.request.post = AsyncMock(return_value=_response(403, "CSRF token missing or invalid"))
    pool = _pool_with_contexts(attacker_context, AsyncMock(), victim_context)
    module = CsrfTestsModule(config=CsrfTestConfig(
        test_role="normal", role_auth_type="form_login",
        victim_role="admin", victim_role_auth_type="form_login",
        allow_state_changing_probes=True,
    ))
    endpoint = _form_endpoint(token=True)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.4"].status == "ERROR"
    assert "baseline" in by_id["TC-130.4"].detail


@pytest.mark.asyncio
async def test_130_4_skipped_when_no_token_field_to_test(tmp_path):
    session_manager = _two_role_session_manager(tmp_path)
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(302, ""))
    pool = _pool_with_context(context)
    module = CsrfTestsModule(config=CsrfTestConfig(
        test_role="normal", role_auth_type="form_login",
        victim_role="admin", victim_role_auth_type="form_login",
        allow_state_changing_probes=True,
    ))
    endpoint = _form_endpoint(token=False)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.4"].status == SKIPPED


# ---------------------------------------------------------------------------
# _samesite_csrf_issue — pure function
# ---------------------------------------------------------------------------


def test_samesite_none_is_always_flagged_even_with_no_other_gap():
    cookie = {"name": "sessionid", "sameSite": "None"}
    issue = _samesite_csrf_issue(cookie, token_field_missing=False, origin_not_validated=False)
    assert issue is not None
    assert "SameSite=None" in issue


def test_samesite_strict_is_never_flagged_even_with_both_other_gaps():
    cookie = {"name": "sessionid", "sameSite": "Strict"}
    issue = _samesite_csrf_issue(cookie, token_field_missing=True, origin_not_validated=True)
    assert issue is None


def test_samesite_lax_flagged_only_when_both_token_and_origin_gaps_present():
    cookie = {"name": "sessionid", "sameSite": "Lax"}
    assert _samesite_csrf_issue(cookie, token_field_missing=True, origin_not_validated=False) is None
    assert _samesite_csrf_issue(cookie, token_field_missing=False, origin_not_validated=True) is None
    assert _samesite_csrf_issue(cookie, token_field_missing=False, origin_not_validated=False) is None
    issue = _samesite_csrf_issue(cookie, token_field_missing=True, origin_not_validated=True)
    assert issue is not None
    assert "TC-130.1" in issue and "TC-130.3" in issue


def test_samesite_absent_treated_like_lax_for_compounding_check():
    cookie = {"name": "sessionid", "sameSite": None}
    assert _samesite_csrf_issue(cookie, token_field_missing=True, origin_not_validated=False) is None
    issue = _samesite_csrf_issue(cookie, token_field_missing=True, origin_not_validated=True)
    assert issue is not None
    assert "Lax default" in issue


# ---------------------------------------------------------------------------
# _candidate_json_api_endpoints — pure function
# ---------------------------------------------------------------------------


def test_candidate_json_api_endpoints_includes_only_json_body_api_endpoints():
    json_api = Endpoint(url="https://x/api/comment", method="POST", endpoint_type="api",
                         parameters=["text"], param_locations={"text": "body"})
    query_only_api = Endpoint(url="https://x/api/search", method="GET", endpoint_type="api",
                               parameters=["q"], param_locations={"q": "query"})
    form = Endpoint(url="https://x/bank/addAccount", method="POST", endpoint_type="form",
                     parameters=["amount"], param_locations={"amount": "body"})

    candidates = _candidate_json_api_endpoints([json_api, query_only_api, form], limit=3)

    assert candidates == [json_api]


# ---------------------------------------------------------------------------
# TC-130.5 — SameSite CSRF relevance (integration, via run_techniques)
# ---------------------------------------------------------------------------


def _cookie(same_site, name="sessionid"):
    return {"name": name, "value": "abc123", "httpOnly": True, "secure": True, "sameSite": same_site}


@pytest.mark.asyncio
async def test_130_5_fails_on_samesite_none_regardless_of_other_gaps(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    auth_context = AsyncMock()
    auth_context.request.post = AsyncMock(return_value=_response(302, "account created"))
    auth_context.cookies = AsyncMock(return_value=[_cookie("None")])
    anon_context = AsyncMock()
    anon_context.cookies = AsyncMock(return_value=[])
    pool = _pool_with_contexts(auth_context, anon_context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _form_endpoint(token=True)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.5"].status == FAIL
    assert by_id["TC-130.5"].finding is not None
    assert "SameSite=None" in by_id["TC-130.5"].finding.description


@pytest.mark.asyncio
async def test_130_5_fails_on_samesite_lax_only_when_compounding_with_130_1_and_130_3(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    auth_context = AsyncMock()
    # No token field on the endpoint (TC-130.1 FAILs) and every submission
    # succeeds regardless of Origin (TC-130.3 FAILs too) -- both other
    # layers are down, so SameSite=Lax being the sole remaining defense is
    # a genuine, non-redundant finding.
    auth_context.request.post = AsyncMock(return_value=_response(302, "account created"))
    auth_context.cookies = AsyncMock(return_value=[_cookie("Lax")])
    anon_context = AsyncMock()
    anon_context.cookies = AsyncMock(return_value=[])
    pool = _pool_with_contexts(auth_context, anon_context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _form_endpoint(token=False)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.1"].status == FAIL
    assert by_id["TC-130.3"].status == FAIL
    assert by_id["TC-130.5"].status == FAIL
    assert "TC-130.1" in by_id["TC-130.5"].finding.description


@pytest.mark.asyncio
async def test_130_5_passes_on_samesite_lax_when_token_field_present(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    auth_context = AsyncMock()
    auth_context.request.post = AsyncMock(return_value=_response(302, "account created"))
    auth_context.cookies = AsyncMock(return_value=[_cookie("Lax")])
    anon_context = AsyncMock()
    anon_context.cookies = AsyncMock(return_value=[])
    pool = _pool_with_contexts(auth_context, anon_context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _form_endpoint(token=True)  # TC-130.1 PASSes -- only one layer down, not compounding

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.1"].status == PASS
    assert by_id["TC-130.5"].status == PASS


@pytest.mark.asyncio
async def test_130_5_passes_on_samesite_strict_even_with_both_other_gaps(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    auth_context = AsyncMock()
    auth_context.request.post = AsyncMock(return_value=_response(302, "account created"))
    auth_context.cookies = AsyncMock(return_value=[_cookie("Strict")])
    anon_context = AsyncMock()
    anon_context.cookies = AsyncMock(return_value=[])
    pool = _pool_with_contexts(auth_context, anon_context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _form_endpoint(token=False)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.1"].status == FAIL
    assert by_id["TC-130.3"].status == FAIL
    assert by_id["TC-130.5"].status == PASS


@pytest.mark.asyncio
async def test_130_5_skipped_when_no_session_cookie_identified(tmp_path):
    # Both the anon and authenticated cookie jars come back empty/identical
    # (e.g. a non-cookie-based auth target) -- no session/auth cookie to
    # evaluate SameSite on at all.
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(302, "account created"))
    pool = _pool_with_context(context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _form_endpoint(token=True)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.5"].status == SKIPPED
    assert "no session/auth cookie identified" in by_id["TC-130.5"].detail


# ---------------------------------------------------------------------------
# TC-130.6 — Content-Type switch bypass (integration, via run_techniques)
# ---------------------------------------------------------------------------


def _json_api_endpoint(url="https://x/api/comment") -> Endpoint:
    return Endpoint(
        url=url, method="POST", endpoint_type="api",
        parameters=["text", "postId"], param_locations={"text": "body", "postId": "body"},
    )


@pytest.mark.asyncio
async def test_130_6_skipped_when_no_json_api_endpoint_discovered(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(302, "account created"))
    pool = _pool_with_context(context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _form_endpoint(token=True)  # a classic form endpoint only -- demo.testfire.net's own shape

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.6"].status == SKIPPED
    assert "no discovered JSON-body-shaped API endpoint" in by_id["TC-130.6"].detail


@pytest.mark.asyncio
async def test_130_6_fails_when_form_urlencoded_resubmission_also_succeeds(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    # The handler accepts the same field data regardless of Content-Type --
    # it doesn't actually gate on JSON.
    context.request.post = AsyncMock(return_value=_response(200, '{"ok": true}'))
    pool = _pool_with_context(context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _json_api_endpoint()

    results = await module.run_techniques([_form_endpoint(token=True), endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.6"].status == FAIL
    assert by_id["TC-130.6"].finding is not None
    assert "x-www-form-urlencoded" in by_id["TC-130.6"].finding.request_raw


@pytest.mark.asyncio
async def test_130_6_passes_when_form_urlencoded_resubmission_is_rejected(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()

    async def fake_post(url, data=None, form=None, headers=None, max_redirects=0):
        if form is not None:  # the form-urlencoded resubmission
            return _response(415, "Unsupported Media Type")
        return _response(200, '{"ok": true}')  # the application/json baseline

    context.request.post = AsyncMock(side_effect=fake_post)
    pool = _pool_with_context(context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _json_api_endpoint()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.6"].status == PASS


@pytest.mark.asyncio
async def test_130_6_errors_when_json_baseline_itself_fails(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = AsyncMock()
    context.request.post = AsyncMock(return_value=_response(403, "Forbidden"))
    pool = _pool_with_context(context)
    module = CsrfTestsModule(config=CsrfTestConfig(test_role="normal", role_auth_type="form_login", allow_state_changing_probes=True))
    endpoint = _json_api_endpoint()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-130.6"].status == "ERROR"
    assert "JSON baseline" in by_id["TC-130.6"].detail
