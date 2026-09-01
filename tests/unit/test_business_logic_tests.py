"""Unit tests for Layer 9 -- stof.modules.business_logic_tests (TC-135)."""
from unittest.mock import AsyncMock

import pytest

from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.business_logic_tests import (
    BusinessLogicTestConfig,
    BusinessLogicTestsModule,
    _find_multistep_flow,
    _find_registration_endpoint,
    _looks_like_signup_success,
    _role_like_param,
    _step_value,
)
from stof.modules.results import FAIL, PASS, SKIPPED

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


def _response(status: int, body: str):
    resp = AsyncMock()
    resp.status = status
    resp.text = AsyncMock(return_value=body)
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


@pytest.mark.asyncio
async def test_run_techniques_skipped_when_no_registration_or_flow_discovered():
    module = BusinessLogicTestsModule(config=BusinessLogicTestConfig(allow_state_changing_probes=True))
    pool = _pool_with_context(_fake_context())

    results = await module.run_techniques([], None, pool)

    by_id = _by_id(results)
    assert len(by_id) == 3
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
