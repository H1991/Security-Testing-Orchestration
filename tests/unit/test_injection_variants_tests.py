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
    _cmd_injection_payloads,
    _csv_formula_survives_unescaped,
    _hpp_pollution_signal,
    _looks_like_xxe_error,
    _nosql_json_body,
    _ssti_evaluation_signal,
    _ssti_payload,
    _xxe_baseline_payload,
    _xxe_file_read_signal,
    _xxe_payload,
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
async def test_run_techniques_returns_all_six_techniques(tmp_path):
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    # A bland, consistently-not-vulnerable-shaped response for whichever
    # of the (ungated) new techniques actually run against this one
    # generic endpoint -- keeps this test about TC-134.1/.2's OWN gate,
    # not about whether the others happen to fire against a mock.
    context = _fake_context(
        get_side_effect=lambda *a, **k: _response(200, "ok"),
        post_side_effect=lambda *a, **k: _response(200, "ok"),
    )
    pool = _pool_with_context(context)
    module = InjectionVariantsTestsModule()  # allow_state_changing_probes defaults False

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = _by_id(results)
    assert len(by_id) == 6
    assert by_id["TC-134.1"].status == SKIPPED
    assert by_id["TC-134.2"].status == SKIPPED
    assert "allow_state_changing_probes" in by_id["TC-134.1"].detail
    assert "allow_state_changing_probes" in by_id["TC-134.2"].detail
    # TC-134.3/.4/.5/.6 are NOT gated behind allow_state_changing_probes
    # (matching sqli_tests.py/xss_tests.py's own convention: a single
    # probe payload isn't gate-worthy, only a real plant/write is) --
    # they still ran, not SKIPPED-for-the-gate-reason.
    for tid in ("TC-134.3", "TC-134.4", "TC-134.5", "TC-134.6"):
        assert "allow_state_changing_probes" not in by_id[tid].detail


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
    assert result.finding.severity == "Medium"  # cvss_score=4.3 -- Medium per the CVSS v3.1 scale (4.0-6.9)


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


# ---------------------------------------------------------------------------
# TC-134.3 OS Command Injection -- pure functions
# ---------------------------------------------------------------------------


def test_cmd_injection_payloads_formats_every_separator_with_the_delay():
    payloads = _cmd_injection_payloads(6.0)
    assert payloads == ("; sleep 6 ;", "| sleep 6", "$(sleep 6)", "`sleep 6`")


def test_cmd_injection_payloads_returns_four_distinct_separator_styles():
    payloads = _cmd_injection_payloads(3.0)
    assert len(set(payloads)) == 4


# ---------------------------------------------------------------------------
# TC-134.3 OS Command Injection -- async
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_command_injection_fails_on_repeatable_delay(tmp_path):
    endpoint = Endpoint(url="https://x/ping", method="GET", endpoint_type="page", parameters=["host"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    call_times = []

    def fake_get(url, params=None, max_redirects=0):
        import time
        call_times.append(time.monotonic())
        value = (params or {}).get("host", "")
        # First separator style (; sleep 6 ;) always "slow"; every other call fast.
        resp = _response(200, "ok")
        if "sleep" in value:
            resp._is_slow = True
        return resp

    async def timed_get(url, params=None, max_redirects=0):
        import asyncio
        value = (params or {}).get("host", "")
        if "sleep" in value:
            await asyncio.sleep(0.05)  # simulated delay, scaled down for test speed
        return fake_get(url, params=params, max_redirects=max_redirects)

    context = _fake_context()
    context.request.get = timed_get
    pool = _pool_with_context(context)
    module = InjectionVariantsTestsModule(config=InjectionVariantsTestConfig(max_cmd_injection_targets=1))
    # Scale the threshold/delay down so the test runs in milliseconds, not seconds.
    import stof.modules.injection_variants_tests as ivt
    original_delay, original_threshold = ivt._CMD_INJECTION_DELAY_S, ivt._CMD_INJECTION_DELTA_THRESHOLD_S
    ivt._CMD_INJECTION_DELAY_S, ivt._CMD_INJECTION_DELTA_THRESHOLD_S = 0.05, 0.03
    try:
        result = await module._technique_command_injection([endpoint], session_manager, pool, evidence=None)
    finally:
        ivt._CMD_INJECTION_DELAY_S, ivt._CMD_INJECTION_DELTA_THRESHOLD_S = original_delay, original_threshold

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.severity == "Critical"


@pytest.mark.asyncio
async def test_command_injection_passes_when_no_delay_observed(tmp_path):
    endpoint = Endpoint(url="https://x/ping", method="GET", endpoint_type="page", parameters=["host"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    def fake_get(url, params=None, max_redirects=0):
        return _response(200, "ok")

    context = _fake_context(get_side_effect=fake_get)
    pool = _pool_with_context(context)
    module = InjectionVariantsTestsModule(config=InjectionVariantsTestConfig(max_cmd_injection_targets=1))

    result = await module._technique_command_injection([endpoint], session_manager, pool, evidence=None)

    assert result.status == PASS


@pytest.mark.asyncio
async def test_command_injection_skipped_when_no_candidates(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = InjectionVariantsTestsModule()

    result = await module._technique_command_injection([], session_manager, pool, evidence=None)

    assert result.status == SKIPPED


# ---------------------------------------------------------------------------
# TC-134.4 XXE -- pure functions
# ---------------------------------------------------------------------------


def test_xxe_payload_declares_external_entity_pointing_at_hostname_file():
    payload = _xxe_payload("marker123")
    assert "SYSTEM" in payload
    assert "file:///etc/hostname" in payload
    assert "marker123-&xxe;-marker123" in payload


def test_xxe_baseline_payload_has_no_doctype():
    baseline = _xxe_baseline_payload("marker123")
    assert "DOCTYPE" not in baseline
    assert "ENTITY" not in baseline


def test_xxe_file_read_signal_true_when_content_substituted():
    payload_body = "<root>marker123-ubuntu-server-01-marker123</root>"
    baseline_body = "<root>marker123-baseline-marker123</root>"
    assert _xxe_file_read_signal(payload_body, baseline_body, "marker123") is True


def test_xxe_file_read_signal_false_when_entity_reference_unresolved():
    # Parser left the literal, unresolved &xxe; in place -- not a real read.
    payload_body = "<root>marker123-&xxe;-marker123</root>"
    baseline_body = "<root>marker123-baseline-marker123</root>"
    assert _xxe_file_read_signal(payload_body, baseline_body, "marker123") is False


def test_xxe_file_read_signal_false_when_markers_absent():
    assert _xxe_file_read_signal("<html>generic error page</html>", "<root>x</root>", "marker123") is False


def test_xxe_file_read_signal_false_when_substituted_content_is_empty():
    payload_body = "<root>marker123--marker123</root>"
    baseline_body = "<root>marker123-baseline-marker123</root>"
    assert _xxe_file_read_signal(payload_body, baseline_body, "marker123") is False


def test_looks_like_xxe_error_matches_known_fingerprint():
    assert _looks_like_xxe_error("Fatal Error: DOCTYPE is not allowed in this context") == "doctype is not allowed"


def test_looks_like_xxe_error_matches_sax_parse_exception_specifically():
    assert _looks_like_xxe_error("com.example.SAXParseException at line 1") == "saxparseexception"


def test_looks_like_xxe_error_none_for_unrelated_body():
    assert _looks_like_xxe_error("<html>Welcome</html>") is None


# ---------------------------------------------------------------------------
# TC-134.4 XXE -- async
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_xxe_fails_on_file_read_differential(tmp_path):
    endpoint = Endpoint(url="https://x/api/import", method="POST", endpoint_type="api", parameters=[])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    def fake_post(url, data=None, headers=None, max_redirects=0):
        if data and "DOCTYPE" in data:
            return _response(200, "<root>stofxxeMARK-ubuntu01-stofxxeMARK</root>")
        return _response(200, "<root>stofxxeMARK-baseline-stofxxeMARK</root>")

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = InjectionVariantsTestsModule(config=InjectionVariantsTestConfig(max_xxe_targets=1))
    module._marker = "MARK"  # deterministic marker for this test

    result = await module._technique_xxe([endpoint], session_manager, pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.severity == "Critical"


@pytest.mark.asyncio
async def test_xxe_fails_with_medium_severity_on_parser_error_fallback(tmp_path):
    endpoint = Endpoint(url="https://x/api/import", method="POST", endpoint_type="api", parameters=[])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    def fake_post(url, data=None, headers=None, max_redirects=0):
        if data and "DOCTYPE" in data:
            return _response(500, "org.xml.sax.SAXParseException: DOCTYPE is not allowed")
        return _response(200, "<root>ok</root>")

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = InjectionVariantsTestsModule(config=InjectionVariantsTestConfig(max_xxe_targets=1))

    result = await module._technique_xxe([endpoint], session_manager, pool, evidence=None)

    assert result.status == FAIL
    assert result.finding.severity == "Medium"


@pytest.mark.asyncio
async def test_xxe_passes_when_no_signal_observed(tmp_path):
    endpoint = Endpoint(url="https://x/api/import", method="POST", endpoint_type="api", parameters=[])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    def fake_post(url, data=None, headers=None, max_redirects=0):
        return _response(200, "<root>rejected, malformed request</root>")

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = InjectionVariantsTestsModule(config=InjectionVariantsTestConfig(max_xxe_targets=1))

    result = await module._technique_xxe([endpoint], session_manager, pool, evidence=None)

    assert result.status == PASS


@pytest.mark.asyncio
async def test_xxe_skipped_when_no_post_endpoints(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = InjectionVariantsTestsModule()

    result = await module._technique_xxe([], session_manager, pool, evidence=None)

    assert result.status == SKIPPED


# ---------------------------------------------------------------------------
# TC-134.5 SSTI -- pure functions
# ---------------------------------------------------------------------------


def test_ssti_payload_is_a_polyglot_across_three_engines():
    payload = _ssti_payload(7, 6)
    assert "{{7*6}}" in payload
    assert "${7*6}" in payload
    assert "<%= 7*6 %>" in payload


def test_ssti_evaluation_signal_true_when_product_present_and_raw_payload_absent():
    payload = _ssti_payload(7, 6)
    body = "Result: 42"
    assert _ssti_evaluation_signal(body, 7, 6, payload) is True


def test_ssti_evaluation_signal_false_when_only_reflected_verbatim():
    payload = _ssti_payload(7, 6)
    body = f"You searched for: {payload}"
    assert _ssti_evaluation_signal(body, 7, 6, payload) is False


def test_ssti_evaluation_signal_false_when_product_absent():
    payload = _ssti_payload(7, 6)
    assert _ssti_evaluation_signal("no match found", 7, 6, payload) is False


# ---------------------------------------------------------------------------
# TC-134.5 SSTI -- async
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ssti_fails_when_expression_evaluated(tmp_path):
    endpoint = Endpoint(url="https://x/render", method="GET", endpoint_type="page", parameters=["name"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    def fake_get(url, params=None, max_redirects=0):
        value = (params or {}).get("name", "")
        if "{{" in value:
            # Simulate Jinja2 evaluating the FIRST polyglot segment only.
            import re
            m = re.search(r"\{\{(\d+)\*(\d+)\}\}", value)
            product = int(m.group(1)) * int(m.group(2))
            return _response(200, f"Hello, {product}${{...}}<%= ... %>!")
        return _response(200, f"Hello, {value}!")

    context = _fake_context(get_side_effect=fake_get)
    pool = _pool_with_context(context)
    module = InjectionVariantsTestsModule(config=InjectionVariantsTestConfig(max_ssti_targets=1))

    result = await module._technique_ssti([endpoint], session_manager, pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.severity == "Critical"


@pytest.mark.asyncio
async def test_ssti_passes_when_payload_only_reflected(tmp_path):
    endpoint = Endpoint(url="https://x/render", method="GET", endpoint_type="page", parameters=["name"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    def fake_get(url, params=None, max_redirects=0):
        value = (params or {}).get("name", "")
        return _response(200, f"Hello, {value}!")

    context = _fake_context(get_side_effect=fake_get)
    pool = _pool_with_context(context)
    module = InjectionVariantsTestsModule(config=InjectionVariantsTestConfig(max_ssti_targets=1))

    result = await module._technique_ssti([endpoint], session_manager, pool, evidence=None)

    assert result.status == PASS


@pytest.mark.asyncio
async def test_ssti_skipped_when_no_candidates(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = InjectionVariantsTestsModule()

    result = await module._technique_ssti([], session_manager, pool, evidence=None)

    assert result.status == SKIPPED


# ---------------------------------------------------------------------------
# TC-134.6 NoSQL Injection -- pure functions
# ---------------------------------------------------------------------------


def test_nosql_json_body_serializes_operator_object():
    body = _nosql_json_body("username", "admin", "password", {"$ne": None})
    assert body == '{"username": "admin", "password": {"$ne": null}}'


def test_nosql_json_body_serializes_gt_operator():
    body = _nosql_json_body("user", "admin", "pass", {"$gt": ""})
    assert '"$gt": ""' in body


# ---------------------------------------------------------------------------
# TC-134.6 NoSQL Injection -- async
# ---------------------------------------------------------------------------


def _login_endpoint():
    return Endpoint(url="https://x/rest/user/login", method="POST", endpoint_type="api", parameters=["email", "password"])


@pytest.mark.asyncio
async def test_nosql_injection_fails_on_operator_auth_bypass():
    endpoint = _login_endpoint()

    def fake_post(url, data=None, headers=None, max_redirects=0):
        if data and "$ne" in data:
            return _response(200, '{"authentication": {"token": "abc123fake"}}')
        return _response(200, '{"error": "invalid credentials"}')

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = InjectionVariantsTestsModule()

    result = await module._technique_nosql_injection([endpoint], pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.severity == "Critical"
    assert "$ne" in result.finding.description or "operator" in result.finding.description.lower()


@pytest.mark.asyncio
async def test_nosql_injection_passes_when_operators_rejected():
    endpoint = _login_endpoint()

    def fake_post(url, data=None, headers=None, max_redirects=0):
        return _response(401, '{"error": "invalid credentials"}')

    context = _fake_context(post_side_effect=fake_post)
    pool = _pool_with_context(context)
    module = InjectionVariantsTestsModule()

    result = await module._technique_nosql_injection([endpoint], pool, evidence=None)

    assert result.status == PASS


@pytest.mark.asyncio
async def test_nosql_injection_skipped_when_no_login_endpoint():
    pool = _pool_with_context(_fake_context())
    module = InjectionVariantsTestsModule()

    result = await module._technique_nosql_injection([], pool, evidence=None)

    assert result.status == SKIPPED
