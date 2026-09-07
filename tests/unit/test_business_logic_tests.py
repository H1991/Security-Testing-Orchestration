"""Unit tests for Layer 9 -- stof.modules.business_logic_tests (TC-135)."""
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthProvider
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.business_logic_tests import (
    BusinessLogicTestConfig,
    BusinessLogicTestsModule,
    _echoes_field_value,
    _find_limited_use_endpoint,
    _find_multistep_flow,
    _find_registration_endpoint,
    _find_workflow_state_create_endpoint,
    _looks_like_signup_success,
    _role_like_param,
    _step_value,
)
from stof.modules.results import FAIL, PASS, SKIPPED
from stof.session.models import Session
from stof.session.session_manager import SessionManager
from stof.session.session_store import SessionStore

# ---------------------------------------------------------------------------
# Pure functions
# ---------------------------------------------------------------------------


def _reg_endpoint(**kwargs):
    defaults = dict(url="https://x/register", method="POST", endpoint_type="form", parameters=["username", "password"])
    defaults.update(kwargs)
    return Endpoint(**defaults)


def test_find_registration_endpoint_matches_path_and_field_hints():
    endpoints = [
        Endpoint(url="https://x/login", method="POST", endpoint_type="form", parameters=["username", "password"]),
        _reg_endpoint(),
    ]
    found = _find_registration_endpoint(endpoints)
    assert found is not None
    assert found.url == "https://x/register"


def test_find_registration_endpoint_none_when_no_candidate():
    endpoints = [Endpoint(url="https://x/login", method="POST", endpoint_type="form", parameters=["username", "password"])]
    assert _find_registration_endpoint(endpoints) is None


def test_role_like_param_detects_privilege_field():
    endpoint = _reg_endpoint(parameters=["username", "password", "role"])
    assert _role_like_param(endpoint) == "role"


def test_role_like_param_none_when_absent():
    endpoint = _reg_endpoint()
    assert _role_like_param(endpoint) is None


def test_looks_like_signup_success_true_on_clean_200():
    assert _looks_like_signup_success(200, "<html>Welcome</html>") is True


def test_looks_like_signup_success_false_on_rejection_signature():
    assert _looks_like_signup_success(200, "Error: username already exists") is False


def test_looks_like_signup_success_false_on_bad_status():
    assert _looks_like_signup_success(500, "<html>Welcome</html>") is False


def test_step_value_parses_query_param():
    assert _step_value("https://x/wizard?step=2") == ("https://x/wizard", 2)


def test_step_value_parses_path_segment():
    prefix, step = _step_value("https://x/checkout/step-3")
    assert step == 3
    assert "{step}" in prefix


def test_step_value_none_when_not_step_shaped():
    assert _step_value("https://x/dashboard") is None


def test_find_multistep_flow_returns_earliest_and_latest():
    endpoints = [
        Endpoint(url="https://x/wizard?step=1", method="GET", endpoint_type="page", parameters=[]),
        Endpoint(url="https://x/wizard?step=3", method="GET", endpoint_type="page", parameters=[]),
        Endpoint(url="https://x/wizard?step=2", method="GET", endpoint_type="page", parameters=[]),
    ]
    flow = _find_multistep_flow(endpoints)
    assert flow is not None
    earliest, latest = flow
    assert earliest.url == "https://x/wizard?step=1"
    assert latest.url == "https://x/wizard?step=3"


def test_find_multistep_flow_none_when_single_step_only():
    endpoints = [Endpoint(url="https://x/wizard?step=1", method="GET", endpoint_type="page", parameters=[])]
    assert _find_multistep_flow(endpoints) is None


# ---------------------------------------------------------------------------
# run_techniques() / individual techniques -- async
# ---------------------------------------------------------------------------


def _response(status: int, body: str, headers: dict | None = None):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
    resp.headers = headers or {}
    return resp


def _fake_context(post_side_effect=None, get_side_effect=None):
    context = AsyncMock()
    if post_side_effect is not None:
        context.request.post = AsyncMock(side_effect=post_side_effect)
    if get_side_effect is not None:
        context.request.get = AsyncMock(side_effect=get_side_effect)
    return context


def _pool_with_context(context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


def _by_id(results):
    return {r.technique_id: r for r in results}


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
    users = {role: UserConfig(id=f"{role}-01", role=role, username=role, password="pw", auth_type="form_login") for role in sessions}
    return SessionManager(users=users, providers={"form_login": _RoutingProvider(sessions)}, store=store)


@pytest.mark.asyncio
async def test_run_techniques_skipped_when_no_registration_or_flow_discovered():
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True))
    pool = _pool_with_context(_fake_context())

    results = await module.run_techniques([], None, pool)

    by_id = _by_id(results)
    assert len(by_id) == 6
    assert all(r.status == SKIPPED for r in by_id.values())


@pytest.mark.asyncio
async def test_reserved_username_gated_skip_when_probes_disabled():
    module = BusinessLogicTestsModule()  # allow_state_changing_probes defaults False
    pool = _pool_with_context(_fake_context())

    result = await module._technique_reserved_username([_reg_endpoint()], pool, evidence=None)

    assert result.status == SKIPPED
    assert "allow_state_changing_probes" in result.detail


@pytest.mark.asyncio
async def test_reserved_username_fails_when_signup_accepted():
    def fake_post(url, form=None, max_redirects=0):
        return _response(201, "<html>Account created successfully, welcome to the site!</html>")

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True))

    result = await module._technique_reserved_username([_reg_endpoint()], pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.severity == "Medium"


@pytest.mark.asyncio
async def test_reserved_username_passes_when_all_rejected():
    def fake_post(url, form=None, max_redirects=0):
        return _response(200, "Error: username already taken")

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True))

    result = await module._technique_reserved_username([_reg_endpoint()], pool, evidence=None)

    assert result.status == PASS


@pytest.mark.asyncio
async def test_self_assigned_privilege_skipped_when_no_role_field():
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True))
    pool = _pool_with_context(_fake_context())

    result = await module._technique_self_assigned_privilege([_reg_endpoint()], pool, evidence=None)

    assert result.status == SKIPPED


@pytest.mark.asyncio
async def test_self_assigned_privilege_fails_when_role_honored():
    endpoint = _reg_endpoint(parameters=["username", "password", "role"])

    def fake_post(url, form=None, max_redirects=0):
        return _response(201, '<html>Welcome, your account was created with "role": "admin" applied</html>')

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True))

    result = await module._technique_self_assigned_privilege([endpoint], pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.severity == "Critical"


@pytest.mark.asyncio
async def test_self_assigned_privilege_passes_when_not_honored():
    endpoint = _reg_endpoint(parameters=["username", "password", "role"])

    def fake_post(url, form=None, max_redirects=0):
        return _response(201, "<html>Welcome, normal user</html>")

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True))

    result = await module._technique_self_assigned_privilege([endpoint], pool, evidence=None)

    assert result.status == PASS


@pytest.mark.asyncio
async def test_workflow_step_skipping_gated_skip_when_probes_disabled():
    endpoints = [
        Endpoint(url="https://x/wizard?step=1", method="GET", endpoint_type="page", parameters=[]),
        Endpoint(url="https://x/wizard?step=3", method="GET", endpoint_type="page", parameters=[]),
    ]
    module = BusinessLogicTestsModule()
    pool = _pool_with_context(_fake_context())

    result = await module._technique_workflow_step_skipping(endpoints, pool, evidence=None)

    assert result.status == SKIPPED
    assert "allow_state_changing_probes" in result.detail


@pytest.mark.asyncio
async def test_workflow_step_skipping_fails_when_later_step_reachable_directly():
    endpoints = [
        Endpoint(url="https://x/wizard?step=1", method="GET", endpoint_type="page", parameters=[]),
        Endpoint(url="https://x/wizard?step=3", method="GET", endpoint_type="page", parameters=[]),
    ]

    def fake_get(url, max_redirects=0):
        return _response(200, "<html>" + ("Final confirmation page content " * 5) + "</html>")

    context = _fake_context(get_side_effect=fake_get)
    pool = _pool_with_context(context)
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True))

    result = await module._technique_workflow_step_skipping(endpoints, pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.severity == "High"


@pytest.mark.asyncio
async def test_workflow_step_skipping_passes_when_rejected():
    endpoints = [
        Endpoint(url="https://x/wizard?step=1", method="GET", endpoint_type="page", parameters=[]),
        Endpoint(url="https://x/wizard?step=3", method="GET", endpoint_type="page", parameters=[]),
    ]

    def fake_get(url, max_redirects=0):
        return _response(200, "Please complete step 1 first")

    context = _fake_context(get_side_effect=fake_get)
    pool = _pool_with_context(context)
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True))

    result = await module._technique_workflow_step_skipping(endpoints, pool, evidence=None)

    assert result.status == PASS


# ---------------------------------------------------------------------------
# TC-135.4 — race condition on a limited-use endpoint
# ---------------------------------------------------------------------------


def test_find_limited_use_endpoint_matches_redeem_path():
    endpoints = [
        Endpoint(url="https://x/login", method="POST", endpoint_type="form", parameters=[]),
        Endpoint(url="https://x/api/redeem-coupon", method="POST", endpoint_type="api", parameters=["code"]),
    ]
    found = _find_limited_use_endpoint(endpoints)
    assert found is not None
    assert found.url == "https://x/api/redeem-coupon"


def test_find_limited_use_endpoint_none_when_no_candidate():
    endpoints = [Endpoint(url="https://x/login", method="POST", endpoint_type="form", parameters=[])]
    assert _find_limited_use_endpoint(endpoints) is None


@pytest.mark.asyncio
async def test_race_condition_skipped_when_no_candidate():
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True))
    pool = _pool_with_context(_fake_context())

    result = await module._technique_race_condition([], pool, evidence=None)

    assert result.status == SKIPPED


@pytest.mark.asyncio
async def test_race_condition_gated_skip_when_probes_disabled():
    endpoints = [Endpoint(url="https://x/redeem", method="POST", endpoint_type="api", parameters=["code"])]
    module = BusinessLogicTestsModule()
    pool = _pool_with_context(_fake_context())

    result = await module._technique_race_condition(endpoints, pool, evidence=None)

    assert result.status == SKIPPED
    assert "allow_state_changing_probes" in result.detail


@pytest.mark.asyncio
async def test_race_condition_fails_when_both_concurrent_requests_succeed():
    endpoints = [Endpoint(url="https://x/redeem", method="POST", endpoint_type="api", parameters=["code"])]

    def fake_post(url, form=None, max_redirects=0):
        return _response(200, "Coupon applied successfully")

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True))

    result = await module._technique_race_condition(endpoints, pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.severity == "Medium"


@pytest.mark.asyncio
async def test_race_condition_passes_when_a_conflict_signal_appears():
    endpoints = [Endpoint(url="https://x/redeem", method="POST", endpoint_type="api", parameters=["code"])]
    call_count = {"n": 0}

    def fake_post(url, form=None, max_redirects=0):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _response(200, "Coupon applied successfully")
        return _response(409, "This coupon has already been used")

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True))

    result = await module._technique_race_condition(endpoints, pool, evidence=None)

    assert result.status == PASS


# ---------------------------------------------------------------------------
# TC-135.5 — sequential over-limit calls to a limited-use endpoint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_function_usage_limit_skipped_when_no_candidate():
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True))
    pool = _pool_with_context(_fake_context())

    result = await module._technique_function_usage_limit([], pool, evidence=None)

    assert result.status == SKIPPED


@pytest.mark.asyncio
async def test_function_usage_limit_gated_skip_when_probes_disabled():
    endpoints = [Endpoint(url="https://x/redeem", method="POST", endpoint_type="api", parameters=["code"])]
    module = BusinessLogicTestsModule()
    pool = _pool_with_context(_fake_context())

    result = await module._technique_function_usage_limit(endpoints, pool, evidence=None)

    assert result.status == SKIPPED
    assert "allow_state_changing_probes" in result.detail


@pytest.mark.asyncio
async def test_function_usage_limit_fails_when_all_three_calls_succeed():
    endpoints = [Endpoint(url="https://x/redeem", method="POST", endpoint_type="api", parameters=["code"])]

    def fake_post(url, form=None, max_redirects=0):
        return _response(200, "Coupon applied successfully")

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True))

    result = await module._technique_function_usage_limit(endpoints, pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.severity == "Medium"


@pytest.mark.asyncio
async def test_function_usage_limit_passes_when_a_later_call_is_rejected():
    endpoints = [Endpoint(url="https://x/redeem", method="POST", endpoint_type="api", parameters=["code"])]
    call_count = {"n": 0}

    def fake_post(url, form=None, max_redirects=0):
        call_count["n"] += 1
        if call_count["n"] < 2:
            return _response(200, "Coupon applied successfully")
        return _response(409, "This coupon has already been used")

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True))

    result = await module._technique_function_usage_limit(endpoints, pool, evidence=None)

    assert result.status == PASS


@pytest.mark.asyncio
async def test_function_usage_limit_sends_exactly_three_sequential_requests():
    endpoints = [Endpoint(url="https://x/redeem", method="POST", endpoint_type="api", parameters=["code"])]
    calls = []

    def fake_post(url, form=None, max_redirects=0):
        calls.append(url)
        return _response(200, "Coupon applied successfully")

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True))

    await module._technique_function_usage_limit(endpoints, pool, evidence=None)

    assert len(calls) == 3


# ---------------------------------------------------------------------------
# TC-135.6 -- workflow-state field accepted at a late-stage value
# ---------------------------------------------------------------------------


def _workflow_endpoint(**kwargs):
    defaults = dict(
        url="https://x/api/articles", method="POST", endpoint_type="api",
        parameters=["title", "status"], param_locations={"status": "body"},
    )
    defaults.update(kwargs)
    return Endpoint(**defaults)


def test_find_workflow_state_create_endpoint_matches_status_field():
    endpoints = [
        Endpoint(url="https://x/api/comments", method="POST", endpoint_type="api", parameters=["body"]),
        _workflow_endpoint(),
    ]
    found = _find_workflow_state_create_endpoint(endpoints)
    assert found is not None
    endpoint, field = found
    assert endpoint.url == "https://x/api/articles"
    assert field == "status"


def test_find_workflow_state_create_endpoint_ignores_put_and_unrelated_fields():
    endpoints = [
        Endpoint(url="https://x/api/articles/1", method="PUT", endpoint_type="api", parameters=["title", "status"]),
        Endpoint(url="https://x/api/users", method="POST", endpoint_type="api", parameters=["state"]),  # US state, not workflow
    ]
    # "state" is in the curated list regardless of semantic meaning --
    # this documents the known, accepted limitation (same "detect a
    # plausible candidate, never assume" tradeoff as every other
    # hint-list technique in this file) rather than silently matching
    # something the pure function's own contract doesn't promise to
    # exclude.
    found = _find_workflow_state_create_endpoint(endpoints)
    assert found is not None
    assert found[0].url == "https://x/api/users"


def test_find_workflow_state_create_endpoint_none_when_no_candidate():
    endpoints = [Endpoint(url="https://x/api/comments", method="POST", endpoint_type="api", parameters=["body"])]
    assert _find_workflow_state_create_endpoint(endpoints) is None


def test_echoes_field_value_matches_regardless_of_spacing_and_quote_style():
    assert _echoes_field_value('{"status": "published", "title": "x"}', "status", "published")
    assert _echoes_field_value("{'status':'PUBLISHED'}", "status", "published")


def test_echoes_field_value_false_when_not_present():
    assert not _echoes_field_value('{"status":"draft"}', "status", "published")


@pytest.mark.asyncio
async def test_workflow_state_skip_skipped_when_no_candidate_endpoint(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True, test_role="normal"))

    result = await module._technique_workflow_state_field_skip([], session_manager, pool, evidence=None)

    assert result.status == SKIPPED
    assert "workflow-state-shaped field" in result.detail


@pytest.mark.asyncio
async def test_workflow_state_skip_gated_when_probes_disabled(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = BusinessLogicTestsModule()  # allow_state_changing_probes defaults False

    result = await module._technique_workflow_state_field_skip([_workflow_endpoint()], session_manager, pool, evidence=None)

    assert result.status == SKIPPED
    assert "disabled by default" in result.detail


@pytest.mark.asyncio
async def test_workflow_state_skip_skipped_when_no_test_role_configured(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True))  # no test_role

    result = await module._technique_workflow_state_field_skip([_workflow_endpoint()], session_manager, pool, evidence=None)

    assert result.status == SKIPPED
    assert "test_role" in result.detail


@pytest.mark.asyncio
async def test_workflow_state_skip_fails_when_late_stage_value_is_accepted_and_echoed(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        import json as json_module
        payload = json_module.loads(data)
        return _response(201, json_module.dumps(payload))  # server honors and echoes back whatever was submitted

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True, test_role="normal", min_content_length=10))

    result = await module._technique_workflow_state_field_skip([_workflow_endpoint()], session_manager, pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.severity == "High"
    assert result.finding.vuln_type == "Business Logic -- Workflow State Field Accepted Out of Sequence"
    assert "published" in result.finding.description  # the first late-stage candidate tried


@pytest.mark.asyncio
async def test_workflow_state_skip_passes_when_server_rejects_every_candidate(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        return _response(201, '{"status":"draft"}')  # server always resets to its own default, never honors the submitted value

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True, test_role="normal"))

    result = await module._technique_workflow_state_field_skip([_workflow_endpoint()], session_manager, pool, evidence=None)

    assert result.status == PASS
    assert result.finding is None
