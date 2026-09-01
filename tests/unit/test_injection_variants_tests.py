"""Unit tests for Layer 9 — stof.modules.injection_variants_tests (TC-134)."""
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthProvider
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.injection_variants_tests import (
    InjectionVariantsTestConfig,
    InjectionVariantsTestsModule,
    _csv_formula_survives_unescaped,
    _hpp_pollution_signal,
)
from stof.modules.results import FAIL, PASS, SKIPPED
from stof.session.models import Session
from stof.session.session_manager import SessionManager
from stof.session.session_store import SessionStore

# ---------------------------------------------------------------------------
# Pure functions
# ---------------------------------------------------------------------------


def test_csv_formula_survives_unescaped_true_on_verbatim_match():
    body = "<td>=1+1+\"stofcsvabc\"</td>"
    assert _csv_formula_survives_unescaped(body, '=1+1+"stofcsvabc"') is True


def test_csv_formula_survives_unescaped_false_when_prefixed_with_quote():
    body = "<td>'=1+1+\"stofcsvabc\"</td>"
    assert _csv_formula_survives_unescaped(body, '=1+1+"stofcsvabc"') is False


def test_csv_formula_survives_unescaped_false_when_absent():
    body = "<td>nothing planted here</td>"
    assert _csv_formula_survives_unescaped(body, '=1+1+"stofcsvabc"') is False


def test_hpp_signal_none_when_polluted_matches_first_value_baseline():
    assert _hpp_pollution_signal("Result: 1", "1", "2", "Result: 1", "Result: 2") is None


def test_hpp_signal_none_when_polluted_matches_last_value_baseline():
    assert _hpp_pollution_signal("Result: 2", "1", "2", "Result: 1", "Result: 2") is None


def test_hpp_signal_flags_when_both_values_reflected_together():
    reason = _hpp_pollution_signal("Result: 1 and 2", "1", "2", "Result: 1", "Result: 2")
    assert reason is not None
    assert "BOTH" in reason


def test_hpp_signal_flags_when_response_matches_neither_baseline():
    reason = _hpp_pollution_signal("Internal Server Error 500", "1", "2", "Result: 1", "Result: 2")
    assert reason is not None
    assert "neither" in reason


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
async def test_run_techniques_skipped_when_state_changing_probes_disabled(tmp_path):
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = InjectionVariantsTestsModule()  # allow_state_changing_probes defaults False

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = _by_id(results)
    assert len(by_id) == 2
    assert all(r.status == SKIPPED for r in by_id.values())
    assert "allow_state_changing_probes" in by_id["TC-134.1"].detail
    assert "allow_state_changing_probes" in by_id["TC-134.2"].detail


# ---------------------------------------------------------------------------
# TC-134.1 HTTP Parameter Pollution
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hpp_fails_when_polluted_response_reflects_both_values(tmp_path):
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["id"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    def fake_get(url, params=None, max_redirects=0):
        if params is not None:
            value = params.get("id")
            return _response(200, f"Result for id={value}")
        # duplicate-key polluted request: both values present in the raw query string
        assert "id=1&id=2" in url
        return _response(200, "Result for id=1 and id=2")

    context = _fake_context(get_side_effect=fake_get)
    pool = _pool_with_context(context)
    module = InjectionVariantsTestsModule(config=InjectionVariantsTestConfig(allow_state_changing_probes=True))

    result = await module._technique_hpp([endpoint], session_manager, pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert "id" in result.finding.description
    assert result.finding.severity == "Low"


@pytest.mark.asyncio
async def test_hpp_passes_when_polluted_response_matches_a_baseline(tmp_path):
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["id"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    def fake_get(url, params=None, max_redirects=0):
        if params is not None:
            value = params.get("id")
            return _response(200, f"Result for id={value}")
        # last-value-wins behavior: polluted response matches the value_b-only baseline
        return _response(200, "Result for id=2")

    context = _fake_context(get_side_effect=fake_get)
    pool = _pool_with_context(context)
    module = InjectionVariantsTestsModule(config=InjectionVariantsTestConfig(allow_state_changing_probes=True))

    result = await module._technique_hpp([endpoint], session_manager, pool, evidence=None)

    assert result.status == PASS


@pytest.mark.asyncio
async def test_hpp_skipped_when_no_injectable_endpoints(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = InjectionVariantsTestsModule(config=InjectionVariantsTestConfig(allow_state_changing_probes=True))

    result = await module._technique_hpp([], session_manager, pool, evidence=None)

    assert result.status == SKIPPED


# ---------------------------------------------------------------------------
# TC-134.2 CSV/Formula injection (plant/verify)
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
async def test_csv_formula_injection_fails_when_marker_survives_unescaped(tmp_path):
    endpoints = _second_order_endpoints()
    session_manager = _session_manager(tmp_path, {
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
    })

    def fake_post(url, form=None, max_redirects=0):
        return _response(200, "Thank you for your feedback")

    captured = {}

    def fake_get(url, max_redirects=0):
        if "admin" in url:
            return _response(200, f"Comment: {captured['payload']}")
        return _response(200, "ok")

    context = _fake_context(get_side_effect=fake_get, post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = InjectionVariantsTestsModule(config=InjectionVariantsTestConfig(allow_state_changing_probes=True))
    captured["payload"] = module._payload_for("TC-134.2")

    result = await module._technique_csv_formula_injection(endpoints, session_manager, pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert "sendFeedback" in result.finding.description
    assert "admin.jsp" in result.finding.description
    assert result.finding.severity == "Medium"


@pytest.mark.asyncio
async def test_csv_formula_injection_passes_when_marker_is_neutralized(tmp_path):
    endpoints = _second_order_endpoints()
    session_manager = _session_manager(tmp_path, {
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
    })

    def fake_post(url, form=None, max_redirects=0):
        return _response(200, "Thank you for your feedback")

    def fake_get(url, max_redirects=0):
        if "admin" in url:
            return _response(200, "Comment: '=1+1+\"neutralized\"")
        return _response(200, "ok")

    context = _fake_context(get_side_effect=fake_get, post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = InjectionVariantsTestsModule(config=InjectionVariantsTestConfig(allow_state_changing_probes=True))

    result = await module._technique_csv_formula_injection(endpoints, session_manager, pool, evidence=None)

    assert result.status == PASS


@pytest.mark.asyncio
async def test_csv_formula_injection_skipped_when_no_free_text_field(tmp_path):
    endpoints = [Endpoint(url="https://x/admin/admin.jsp", method="GET", endpoint_type="page")]
    session_manager = _session_manager(tmp_path, {
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
    })
    pool = _pool_with_context(_fake_context())
    module = InjectionVariantsTestsModule(config=InjectionVariantsTestConfig(allow_state_changing_probes=True))

    result = await module._technique_csv_formula_injection(endpoints, session_manager, pool, evidence=None)

    assert result.status == SKIPPED
