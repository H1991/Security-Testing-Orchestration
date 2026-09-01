"""Unit tests for Layer 9 — stof.modules.idor_tests.

Fakes `SessionManager` (real class, real `SessionStore` on tmp_path,
fake `AuthProvider`) + `SessionPool` (real class, `AsyncMock` browser
whose `new_context()` returns a hand-built fake context exposing just
`request.get`/`new_page`/`add_cookies`/`set_extra_http_headers`) --
same combination `test_session_manager.py` and `test_multi_session.py`
each use individually.

Candidate parameter/URL names below are deliberately the real ones this
project confirmed on demo.testfire.net (`listAccounts`, `/admin/
admin.jsp`) -- these tests are a regression guard that the module
actually catches the real, hand-verified findings it was built from.
"""
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthProvider
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.findings.models import Finding
from stof.modules.idor_tests import IdorTestConfig, IdorTestsModule, _looks_like_object_reference, _set_query_param
from stof.modules.results import ERROR, FAIL, PASS, SKIPPED
from stof.session.models import Session
from stof.session.session_manager import SessionManager
from stof.session.session_store import SessionStore


def _user(role: str) -> UserConfig:
    return UserConfig(id=f"{role}-01", role=role, username=role, password="pw", auth_type="form_login")


class _RoutingProvider(AuthProvider):
    """SessionManager keys providers by auth_type, shared across roles in
    Phase 1 -- every fake session below uses form_login, so a single
    provider must route to the right role's session by looking at which
    user it was asked to authenticate."""

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


def _fake_context(get_side_effect):
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=AsyncMock())
    context.request.get = AsyncMock(side_effect=get_side_effect)
    return context


def _pool_with_context(context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_set_query_param_replaces_existing_value():
    url = _set_query_param("https://x/bank/showAccount?listAccounts=800000", "listAccounts", "800001")
    assert url == "https://x/bank/showAccount?listAccounts=800001"


def test_set_query_param_adds_missing_param():
    url = _set_query_param("https://x/api/users", "id", "5")
    assert url == "https://x/api/users?id=5"


def test_looks_like_object_reference_matches_the_real_listaccounts_param():
    """Regression: guess_param_type("listAccounts") alone returns
    "string" (no id/number heuristic matches), which would have missed
    this project's own confirmed real IDOR parameter entirely."""
    assert _looks_like_object_reference("listAccounts") is True


def test_looks_like_object_reference_matches_plain_id():
    assert _looks_like_object_reference("id") is True


def test_looks_like_object_reference_rejects_unrelated_param():
    assert _looks_like_object_reference("theme") is False


# ---------------------------------------------------------------------------
# Horizontal IDOR — happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_horizontal_idor_flags_distinct_objects_from_one_session(tmp_path):
    endpoint = Endpoint(
        url="https://x/bank/showAccount", method="GET", endpoint_type="api",
        parameters=["listAccounts"], auth_required=True,
    )
    admin_session = Session(user_id="admin-01", role="admin", auth_type="form_login", cookies={"JSESSIONID": "abc"})
    session_manager = _session_manager(tmp_path, {"admin": admin_session})

    bodies = {"1": "Account #1 balance $500" * 20, "2": "Account #2 balance $9000" * 20}

    async def fake_get(url, max_redirects=0):
        cid = url.rsplit("=", 1)[-1]
        if cid in bodies:
            return _response(200, bodies[cid])
        return _response(500, "error")

    pool = _pool_with_context(_fake_context(fake_get))
    module = IdorTestsModule(config=IdorTestConfig(candidate_ids=["1", "2", "3"]))

    findings = await module.run([endpoint], session_manager, pool)

    assert len(findings) == 1
    assert findings[0].vuln_type.startswith("Insecure Direct Object Reference")
    assert findings[0].user_role == "admin"
    assert findings[0].severity == "Critical"


@pytest.mark.asyncio
async def test_horizontal_idor_populates_evidence_refs_when_collector_supplied(tmp_path):
    endpoint = Endpoint(
        url="https://x/bank/showAccount", method="GET", endpoint_type="api",
        parameters=["listAccounts"], auth_required=True,
    )
    admin_session = Session(user_id="admin-01", role="admin", auth_type="form_login", cookies={"JSESSIONID": "abc"})
    session_manager = _session_manager(tmp_path, {"admin": admin_session})
    bodies = {"1": "Account #1 balance $500" * 20, "2": "Account #2 balance $9000" * 20}

    async def fake_get(url, max_redirects=0):
        cid = url.rsplit("=", 1)[-1]
        return _response(200, bodies[cid]) if cid in bodies else _response(500, "error")

    pool = _pool_with_context(_fake_context(fake_get))
    evidence = AsyncMock()
    evidence.capture = AsyncMock(return_value=["data/evidence/scan-1/idor/screenshot.png"])
    module = IdorTestsModule(config=IdorTestConfig(candidate_ids=["1", "2"]))

    findings = await module.run([endpoint], session_manager, pool, evidence=evidence)

    assert len(findings) == 1
    assert findings[0].evidence_refs == ["data/evidence/scan-1/idor/screenshot.png"]
    evidence.capture.assert_awaited_once()


# ---------------------------------------------------------------------------
# Horizontal IDOR — cross-session confirmation (candidate vs. confirmed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_horizontal_idor_confirms_finding_when_a_second_identity_can_also_access_the_objects(tmp_path):
    """A single session enumerating IDs only proves "this role can see
    multiple objects" -- proof of an actual cross-user authorization
    gap requires a genuinely different identity replaying the same
    object IDs and succeeding too. Live-verified against a real
    target: an admin session found 3 distinct accounts, and a
    completely different 'normal' session could pull every one of
    them -- this is that exact scenario."""
    endpoint = Endpoint(
        url="https://x/bank/showAccount", method="GET", endpoint_type="api",
        parameters=["listAccounts"], auth_required=True,
    )
    admin_session = Session(user_id="admin-01", role="admin", auth_type="form_login", cookies={"JSESSIONID": "abc"})
    normal_session = Session(user_id="normal-01", role="normal", auth_type="form_login", cookies={"JSESSIONID": "def"})
    session_manager = _session_manager(tmp_path, {"admin": admin_session, "normal": normal_session})
    bodies = {"1": "Account #1 balance $500" * 20, "2": "Account #2 balance $9000" * 20}

    async def fake_get(url, max_redirects=0):
        cid = url.rsplit("=", 1)[-1]
        return _response(200, bodies[cid]) if cid in bodies else _response(500, "error")

    admin_context = _fake_context(fake_get)
    normal_context = _fake_context(fake_get)  # same objects accessible -- no ownership check at all
    browser = AsyncMock()
    pool = SessionPool(browser)
    pool._contexts["admin"] = admin_context
    pool._contexts["normal"] = normal_context
    module = IdorTestsModule(config=IdorTestConfig(candidate_ids=["1", "2"]))

    findings = await module.run([endpoint], session_manager, pool)

    assert len(findings) == 1
    assert "CONFIRMED via a second identity" in findings[0].description
    assert "'normal'" in findings[0].description


@pytest.mark.asyncio
async def test_horizontal_idor_no_finding_when_a_second_identity_is_denied_every_object(tmp_path):
    """The other half of the same fix: a second identity correctly
    denied every object the first identity could see means real
    per-user access control may be present -- this must NOT still be
    reported as a Critical finding just because one session enumerated
    distinct objects."""
    endpoint = Endpoint(
        url="https://x/bank/showAccount", method="GET", endpoint_type="api",
        parameters=["listAccounts"], auth_required=True,
    )
    admin_session = Session(user_id="admin-01", role="admin", auth_type="form_login", cookies={"JSESSIONID": "abc"})
    normal_session = Session(user_id="normal-01", role="normal", auth_type="form_login", cookies={"JSESSIONID": "def"})
    session_manager = _session_manager(tmp_path, {"admin": admin_session, "normal": normal_session})
    bodies = {"1": "Account #1 balance $500" * 20, "2": "Account #2 balance $9000" * 20}

    async def admin_get(url, max_redirects=0):
        cid = url.rsplit("=", 1)[-1]
        return _response(200, bodies[cid]) if cid in bodies else _response(500, "error")

    async def normal_get(url, max_redirects=0):
        return _response(403, "Forbidden")  # real ownership check -- denied every time

    admin_context = _fake_context(admin_get)
    normal_context = _fake_context(normal_get)
    browser = AsyncMock()
    pool = SessionPool(browser)
    pool._contexts["admin"] = admin_context
    pool._contexts["normal"] = normal_context
    module = IdorTestsModule(config=IdorTestConfig(candidate_ids=["1", "2"]))

    findings = await module.run([endpoint], session_manager, pool)

    assert findings == []


@pytest.mark.asyncio
async def test_horizontal_idor_falls_back_to_unconfirmed_when_no_second_role_configured(tmp_path):
    """Preserves the pre-existing single-identity signal (clearly
    caveated, per `_idor_description()`) when there's no distinct
    low-priv role to cross-validate with -- must not silently lose
    coverage for a target with only one usable test account."""
    endpoint = Endpoint(
        url="https://x/bank/showAccount", method="GET", endpoint_type="api",
        parameters=["listAccounts"], auth_required=True,
    )
    admin_session = Session(user_id="admin-01", role="admin", auth_type="form_login", cookies={"JSESSIONID": "abc"})
    session_manager = _session_manager(tmp_path, {"admin": admin_session})
    bodies = {"1": "Account #1 balance $500" * 20, "2": "Account #2 balance $9000" * 20}

    async def fake_get(url, max_redirects=0):
        cid = url.rsplit("=", 1)[-1]
        return _response(200, bodies[cid]) if cid in bodies else _response(500, "error")

    pool = _pool_with_context(_fake_context(fake_get))
    module = IdorTestsModule(config=IdorTestConfig(candidate_ids=["1", "2"]))

    findings = await module.run([endpoint], session_manager, pool)

    assert len(findings) == 1
    assert "Unconfirmed with a second identity" in findings[0].description


@pytest.mark.asyncio
async def test_horizontal_idor_no_finding_when_all_candidates_return_same_content(tmp_path):
    """E.g. every ID redirects to the same "please log in" page --
    no evidence of cross-object access, just one uniform response."""
    endpoint = Endpoint(
        url="https://x/bank/showAccount", method="GET", endpoint_type="api",
        parameters=["listAccounts"], auth_required=True,
    )
    admin_session = Session(user_id="admin-01", role="admin", auth_type="form_login", cookies={})
    session_manager = _session_manager(tmp_path, {"admin": admin_session})

    same_body = "Please log in" * 20

    async def fake_get(url, max_redirects=0):
        return _response(200, same_body)

    pool = _pool_with_context(_fake_context(fake_get))
    module = IdorTestsModule(config=IdorTestConfig(candidate_ids=["1", "2"]))

    findings = await module.run([endpoint], session_manager, pool)

    assert findings == []


@pytest.mark.asyncio
async def test_horizontal_idor_ignores_endpoints_without_object_reference_params(tmp_path):
    endpoint = Endpoint(url="https://x/settings", method="GET", endpoint_type="page", parameters=["theme"])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="admin-01", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_context(AsyncMock()))
    module = IdorTestsModule()

    findings = await module.run([endpoint], session_manager, pool)

    assert findings == []


# ---------------------------------------------------------------------------
# Vertical privilege escalation — happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_vertical_privesc_flags_normal_user_reaching_admin_panel(tmp_path):
    endpoint = Endpoint(url="https://x/admin/admin.jsp", method="GET", endpoint_type="page", parameters=[])
    normal_session = Session(user_id="user-01", role="normal", auth_type="form_login", cookies={"JSESSIONID": "abc"})
    session_manager = _session_manager(tmp_path, {"normal": normal_session})

    async def fake_get(url, max_redirects=0):
        return _response(200, "Admin Panel content" * 50)

    pool = _pool_with_context(_fake_context(fake_get))
    module = IdorTestsModule(low_priv_role="normal")

    findings = await module.run([endpoint], session_manager, pool)

    assert len(findings) == 1
    assert "Privilege Escalation" in findings[0].vuln_type
    assert findings[0].user_role == "normal"


@pytest.mark.asyncio
async def test_vertical_privesc_dedupes_same_url_discovered_via_multiple_methods(tmp_path):
    """Regression: confirmed against this project's own demo target --
    the crawler discovered /admin/admin.jsp as both a GET page and a
    POST form, which produced a duplicate finding before URL-based
    dedup was added here."""
    endpoints = [
        Endpoint(url="https://x/admin/admin.jsp", method="GET", endpoint_type="page", parameters=[]),
        Endpoint(url="https://x/admin/admin.jsp", method="POST", endpoint_type="form", parameters=[]),
    ]
    normal_session = Session(user_id="user-01", role="normal", auth_type="form_login")
    session_manager = _session_manager(tmp_path, {"normal": normal_session})

    async def fake_get(url, max_redirects=0):
        return _response(200, "Admin Panel content" * 50)

    pool = _pool_with_context(_fake_context(fake_get))
    module = IdorTestsModule(low_priv_role="normal")

    findings = await module.run(endpoints, session_manager, pool)

    assert len(findings) == 1


@pytest.mark.asyncio
async def test_vertical_privesc_no_finding_when_access_denied(tmp_path):
    endpoint = Endpoint(url="https://x/admin/admin.jsp", method="GET", endpoint_type="page", parameters=[])
    normal_session = Session(user_id="user-01", role="normal", auth_type="form_login")
    session_manager = _session_manager(tmp_path, {"normal": normal_session})

    async def fake_get(url, max_redirects=0):
        return _response(302, "")

    pool = _pool_with_context(_fake_context(fake_get))
    module = IdorTestsModule(low_priv_role="normal")

    findings = await module.run([endpoint], session_manager, pool)

    assert findings == []


@pytest.mark.asyncio
async def test_vertical_privesc_ignores_non_privileged_looking_endpoints(tmp_path):
    endpoint = Endpoint(url="https://x/bank/main.jsp", method="GET", endpoint_type="page", parameters=[])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="user-01", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context(AsyncMock()))
    module = IdorTestsModule(low_priv_role="normal")

    findings = await module.run([endpoint], session_manager, pool)

    assert findings == []


# ---------------------------------------------------------------------------
# Role parameter tampering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_role_tampering_flags_client_controlled_role_param(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=["role"])
    normal_session = Session(user_id="user-01", role="normal", auth_type="form_login")
    session_manager = _session_manager(tmp_path, {"normal": normal_session})

    async def fake_get(url, max_redirects=0):
        if "role=admin" in url:
            return _response(200, "Admin dashboard data" * 20)
        return _response(200, "Normal user profile" * 20)

    pool = _pool_with_context(_fake_context(fake_get))
    module = IdorTestsModule(low_priv_role="normal")

    findings = await module.run([endpoint], session_manager, pool)

    role_findings = [f for f in findings if f.vuln_type == "Role Manipulation via Parameter Tampering"]
    assert len(role_findings) == 1
    assert role_findings[0].severity == "Critical"


@pytest.mark.asyncio
async def test_role_tampering_no_finding_when_no_role_like_params_discovered(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="GET", endpoint_type="api", parameters=["name"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="user-01", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context(AsyncMock()))
    module = IdorTestsModule(low_priv_role="normal")

    findings = await module.run([endpoint], session_manager, pool)

    assert findings == []
    pool_context = await pool.get_context("normal")
    pool_context.request.get.assert_not_called()


# ---------------------------------------------------------------------------
# Input validation / failure handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_skips_test_when_role_not_configured_instead_of_crashing(tmp_path):
    """high_priv_role defaults to 'admin', but only 'normal' is
    configured here -- the horizontal-IDOR test should be skipped
    (KeyError caught), not crash the whole module."""
    endpoint = Endpoint(
        url="https://x/bank/showAccount", method="GET", endpoint_type="api",
        parameters=["listAccounts"],
    )
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="user-01", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context(AsyncMock()))
    module = IdorTestsModule(high_priv_role="admin", low_priv_role="normal")

    findings = await module.run([endpoint], session_manager, pool)

    assert findings == []


@pytest.mark.asyncio
async def test_run_with_no_endpoints_returns_no_findings(tmp_path):
    session_manager = _session_manager(tmp_path, {})
    pool = _pool_with_context(_fake_context(AsyncMock()))
    module = IdorTestsModule()

    findings = await module.run([], session_manager, pool)

    assert findings == []


# ---------------------------------------------------------------------------
# Payload-registry migration (Step 2, TC-053 only): TC-053.1 (path) and
# TC-053.2 (query) now source their candidate ids through
# `self.payload_registry` instead of reading `self.config.candidate_ids`
# directly. Every test above this point already proves request/finding
# behavior is unchanged (same assertions, still passing); these confirm
# the registry itself is genuinely populated and consulted.
# ---------------------------------------------------------------------------


def test_module_registers_candidate_ids_as_tc053_payloads_on_construction():
    module = IdorTestsModule(config=IdorTestConfig(candidate_ids=["800000", "800001"]))

    path_payloads = module.payload_registry.for_testcase("TC-053.1")
    query_payloads = module.payload_registry.for_testcase("TC-053.2")

    assert [p.value for p in path_payloads] == ["800000", "800001"]
    assert all(p.contexts == ("path",) for p in path_payloads)
    assert [p.value for p in query_payloads] == ["800000", "800001"]
    assert all(p.contexts == ("query",) for p in query_payloads)


@pytest.mark.asyncio
async def test_horizontal_idor_uses_custom_candidate_ids_via_the_payload_registry(tmp_path):
    """A custom `candidate_ids` list must flow all the way through the
    registry into the actual probe -- not just get registered and then
    ignored in favor of the old config-direct read."""
    endpoint = Endpoint(
        url="https://x/bank/showAccount", method="GET", endpoint_type="api",
        parameters=["listAccounts"], auth_required=True,
    )
    admin_session = Session(user_id="admin-01", role="admin", auth_type="form_login", cookies={"JSESSIONID": "abc"})
    session_manager = _session_manager(tmp_path, {"admin": admin_session})
    bodies = {"9001": "Account #9001 balance $500" * 20, "9002": "Account #9002 balance $9000" * 20}
    seen_ids: list[str] = []

    async def fake_get(url, max_redirects=0):
        cid = url.rsplit("=", 1)[-1]
        seen_ids.append(cid)
        return _response(200, bodies[cid]) if cid in bodies else _response(500, "error")

    pool = _pool_with_context(_fake_context(fake_get))
    module = IdorTestsModule(config=IdorTestConfig(candidate_ids=["9001", "9002"]))

    findings = await module.run([endpoint], session_manager, pool)

    assert seen_ids == ["9001", "9002"]
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_idor_path_param_uses_custom_candidate_ids_via_the_payload_registry(tmp_path):
    endpoint = Endpoint(url="https://x/api/orders/1", method="GET", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    bodies = {"9001": "Order #9001" * 20, "9002": "Order #9002" * 20}
    seen_ids: list[str] = []

    async def fake_get(url, max_redirects=0):
        cid = url.rsplit("/", 1)[-1]
        seen_ids.append(cid)
        return _response(200, bodies[cid]) if cid in bodies else _response(404, "not found")

    pool = _pool_with_context(_fake_context(fake_get))
    module = IdorTestsModule(config=IdorTestConfig(candidate_ids=["9001", "9002"]))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-053.1"].status == FAIL
    assert seen_ids == ["9001", "9002"]


# ---------------------------------------------------------------------------
# Transient-auth-failure resilience & honest ERROR reporting
#
# Regression for a real scan: a single `net::ERR_NETWORK_CHANGED` during
# admin authentication propagated out of `_test_horizontal_idor`, aborted
# all three base tests, was swallowed by `_safe` into an empty result,
# and the famous AltoroMutual `showAccount?listAccounts=` IDOR reported
# PASS ("target resisted") when it had never actually run. Two fixes:
# (1) `_authenticated_context` retries transient errors, so the real IDOR
# survives a blip; (2) an exhausted/genuine base-test error surfaces as
# ERROR, never a false PASS.
# ---------------------------------------------------------------------------


class _FlakyRoutingProvider(AuthProvider):
    """Raises a transient-looking error on the first N `authenticate`
    calls for `flaky_role`, then behaves like `_RoutingProvider`."""

    def __init__(self, sessions: dict, flaky_role: str, fail_times: int) -> None:
        self._sessions = sessions
        self._flaky_role = flaky_role
        self._remaining = fail_times

    async def authenticate(self, user, page):
        if user.role == self._flaky_role and self._remaining > 0:
            self._remaining -= 1
            raise RuntimeError("Page.goto: net::ERR_NETWORK_CHANGED at https://x/login.jsp")
        return self._sessions[user.role]

    async def refresh(self, session, page):
        raise NotImplementedError

    async def is_authenticated(self, session, page) -> bool:
        return True


def _flaky_session_manager(tmp_path, sessions: dict, flaky_role: str, fail_times: int) -> SessionManager:
    store = SessionStore(db_path=tmp_path / "stof.db")
    users = {role: _user(role) for role in sessions}
    return SessionManager(users=users, providers={"form_login": _FlakyRoutingProvider(sessions, flaky_role, fail_times)}, store=store)


@pytest.fixture
def _instant_sleep(monkeypatch):
    # `_authenticated_context`'s retry-with-backoff now lives in
    # `stof.modules.base` (promoted there in Batch 3 so every VulnModule
    # gets the same transient-error retry, not just IdorTestsModule).
    monkeypatch.setattr("stof.modules.base.asyncio.sleep", AsyncMock(return_value=None))


@pytest.mark.asyncio
async def test_horizontal_idor_survives_a_transient_auth_failure_via_retry(tmp_path, _instant_sleep):
    """The real fix: one transient network error during admin auth must
    NOT lose the IDOR finding -- `_authenticated_context` retries and
    the finding is still produced."""
    endpoint = Endpoint(
        url="https://x/bank/showAccount", method="GET", endpoint_type="api",
        parameters=["listAccounts"], auth_required=True,
    )
    sessions = {
        "admin": Session(user_id="admin-01", role="admin", auth_type="form_login", cookies={"JSESSIONID": "abc"}),
        "normal": Session(user_id="normal-01", role="normal", auth_type="form_login", cookies={"JSESSIONID": "def"}),
    }
    session_manager = _flaky_session_manager(tmp_path, sessions, flaky_role="admin", fail_times=1)
    bodies = {"1": "Account #1 balance $500" * 20, "2": "Account #2 balance $9000" * 20}

    async def fake_get(url, max_redirects=0):
        cid = url.rsplit("=", 1)[-1]
        return _response(200, bodies[cid]) if cid in bodies else _response(500, "error")

    browser = AsyncMock()
    pool = SessionPool(browser)
    pool._contexts["admin"] = _fake_context(fake_get)
    pool._contexts["normal"] = _fake_context(fake_get)
    module = IdorTestsModule(config=IdorTestConfig(candidate_ids=["1", "2"]))

    findings = await module.run([endpoint], session_manager, pool)

    assert len(findings) == 1
    assert "CONFIRMED via a second identity" in findings[0].description
    assert module._base_test_errors == {}  # retry recovered -- no error recorded


@pytest.mark.asyncio
async def test_reused_result_reports_error_not_pass_when_base_test_cannot_authenticate(tmp_path, _instant_sleep):
    """The honesty fix: when the base horizontal-IDOR test cannot run at
    all (transient error survives every retry), TC-053.2 must report
    ERROR, never PASS -- a PASS there would claim the target resisted an
    attack that was never sent."""
    endpoint = Endpoint(
        url="https://x/bank/showAccount", method="GET", endpoint_type="api",
        parameters=["listAccounts"], auth_required=True,
    )
    sessions = {
        "admin": Session(user_id="admin-01", role="admin", auth_type="form_login", cookies={"JSESSIONID": "abc"}),
        "normal": Session(user_id="normal-01", role="normal", auth_type="form_login", cookies={"JSESSIONID": "def"}),
    }
    # admin auth fails on every attempt -> retries exhausted -> horizontal
    # IDOR base test errors. normal still authenticates fine.
    session_manager = _flaky_session_manager(tmp_path, sessions, flaky_role="admin", fail_times=99)

    async def fake_get(url, max_redirects=0):
        return _response(200, "content" * 30)

    browser = AsyncMock()
    pool = SessionPool(browser)
    pool._contexts["admin"] = _fake_context(fake_get)
    pool._contexts["normal"] = _fake_context(fake_get)
    module = IdorTestsModule(config=IdorTestConfig(candidate_ids=["1", "2"]))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-053.2"].status == ERROR
    assert by_id["TC-053.2"].status != PASS
    assert "could not complete" in by_id["TC-053.2"].detail
    assert "horizontal_idor" in module._base_test_errors


@pytest.mark.asyncio
async def test_base_test_error_does_not_abort_the_other_base_tests(tmp_path, _instant_sleep):
    """A network error in one base test (horizontal IDOR, auths admin)
    must no longer abort the other two (they auth normal) -- previously
    the un-caught exception broke out of run()'s loop entirely."""
    # showAccount triggers horizontal IDOR's admin auth (which fails);
    # admin.jsp triggers vertical priv-esc as the low-priv normal role.
    idor_endpoint = Endpoint(url="https://x/bank/showAccount", method="GET", endpoint_type="api", parameters=["listAccounts"])
    admin_page = Endpoint(url="https://x/admin/admin.jsp", method="GET", endpoint_type="page")
    sessions = {
        "admin": Session(user_id="admin-01", role="admin", auth_type="form_login", cookies={"JSESSIONID": "abc"}),
        "normal": Session(user_id="normal-01", role="normal", auth_type="form_login", cookies={"JSESSIONID": "def"}),
    }
    session_manager = _flaky_session_manager(tmp_path, sessions, flaky_role="admin", fail_times=99)

    async def fake_get(url, max_redirects=0):
        return _response(200, "admin panel content" * 30)  # low-priv sees admin page -> vertical priv-esc finding

    browser = AsyncMock()
    pool = SessionPool(browser)
    pool._contexts["admin"] = _fake_context(fake_get)
    pool._contexts["normal"] = _fake_context(fake_get)
    module = IdorTestsModule(config=IdorTestConfig(candidate_ids=["1", "2"]))

    findings = await module.run([idor_endpoint, admin_page], session_manager, pool)

    # horizontal IDOR (admin) errored, but vertical priv-esc (normal) still ran and found the admin page
    assert "horizontal_idor" in module._base_test_errors
    assert any("Privilege Escalation" in f.vuln_type for f in findings)


# ---------------------------------------------------------------------------
# TC-053.6 — object-id predictability analysis (analytical, no new requests)
# ---------------------------------------------------------------------------


def _idor_module() -> IdorTestsModule:
    return IdorTestsModule(config=IdorTestConfig())


def test_id_predictability_skips_when_too_few_ids_observed():
    """This project's demo target uses account ids 800000/800001 --
    exactly two of them isn't enough to call anything "sequential":
    a single pair of small integers could just as easily be
    coincidence, so the minimum-sample-size guard must SKIP, not FAIL,
    below the threshold."""
    endpoints = [
        Endpoint(url="https://x/bank/showAccount?listAccounts=800000", method="GET", endpoint_type="api", parameters=["listAccounts"]),
        Endpoint(url="https://x/bank/showAccount?listAccounts=800001", method="GET", endpoint_type="api", parameters=["listAccounts"]),
    ]
    results = _idor_module()._technique_id_predictability_analysis(endpoints)
    assert len(results) == 1
    assert results[0].status == SKIPPED
    assert results[0].technique_id == "TC-053.6"
    assert "too few" in results[0].detail


def test_id_predictability_fails_on_sequential_integer_ids():
    """This project's own demo target (demo.testfire.net) uses exactly
    this shape -- TC-053's own idor_candidate_ids config
    (800000-800010) is a plain incrementing integer range, the classic
    auto-increment-primary-key-as-external-id pattern."""
    endpoints = [
        Endpoint(url=f"https://x/bank/showAccount?listAccounts=80000{i}", method="GET", endpoint_type="api", parameters=["listAccounts"])
        for i in range(6)
    ]
    results = _idor_module()._technique_id_predictability_analysis(endpoints)
    assert len(results) == 1
    assert results[0].status == FAIL
    assert results[0].technique_id == "TC-053.6"
    assert "sequential" in results[0].detail.lower()


def test_id_predictability_passes_on_uuid_shaped_ids():
    endpoints = [
        Endpoint(url=f"https://x/api/orders/{uuid}", method="GET", endpoint_type="api")
        for uuid in [
            "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            "550e8400-e29b-41d4-a716-446655440000",
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
            "6ba7b812-9dad-11d1-80b4-00c04fd430c8",
        ]
    ]
    results = _idor_module()._technique_id_predictability_analysis(endpoints)
    assert len(results) == 1
    assert results[0].status == PASS
    assert results[0].technique_id == "TC-053.6"


def test_id_predictability_dedupes_repeated_ids_across_endpoints():
    """The same id showing up on multiple discovered endpoints must not
    inflate the sample -- 5 endpoints all referencing only 2 distinct
    ids is still below the minimum sample size."""
    endpoints = [
        Endpoint(url="https://x/bank/showAccount?listAccounts=800000", method="GET", endpoint_type="api", parameters=["listAccounts"])
        for _ in range(3)
    ] + [
        Endpoint(url="https://x/bank/showAccount?listAccounts=800001", method="GET", endpoint_type="api", parameters=["listAccounts"])
        for _ in range(3)
    ]
    results = _idor_module()._technique_id_predictability_analysis(endpoints)
    assert results[0].status == SKIPPED


@pytest.mark.asyncio
async def test_id_predictability_draws_ids_from_base_findings_when_endpoints_alone_are_too_few():
    """Regression for the real demo.testfire.net scan shape: the
    crawler only ever discovers the bare '/bank/showAccount' URL with
    no query string, so `endpoints` alone never carries the 11
    sequential account ids -- they only ever appear inside TC-053.2's
    own confirmed Finding (request_raw/response_raw), which this
    technique must also read (already-observed data, zero new
    requests) to avoid a false SKIP on exactly the target this project
    was built against."""
    bare_endpoint = Endpoint(url="https://x/bank/showAccount", method="GET", endpoint_type="api", parameters=["listAccounts"])
    sample_ids = [str(800000 + i) for i in range(6)]
    finding = Finding(
        module_id="idor_tests", vuln_type="Insecure Direct Object Reference (IDOR)", severity="Critical", cvss_score=8.1,
        endpoint=bare_endpoint, user_role="admin",
        request_raw="\n".join(f"GET https://x/bank/showAccount?listAccounts={cid}" for cid in sample_ids),
        response_raw="\n".join(f"[listAccounts={cid}] HTTP 200, 500 bytes" for cid in sample_ids),
        description="...", recommendation="...",
    )
    results = _idor_module()._technique_id_predictability_analysis([bare_endpoint], base_findings=[finding])
    assert len(results) == 1
    assert results[0].status == FAIL
    assert results[0].technique_id == "TC-053.6"


@pytest.mark.asyncio
async def test_id_predictability_wired_into_run_techniques(tmp_path):
    """Regression: TC-053.6 must actually be reachable through
    run_techniques(), not just directly callable, otherwise a live scan
    would never surface it."""
    sessions = {
        "admin": Session(user_id="admin-01", role="admin", auth_type="form_login", cookies={"JSESSIONID": "abc"}),
        "normal": Session(user_id="normal-01", role="normal", auth_type="form_login", cookies={"JSESSIONID": "def"}),
    }
    session_manager = _session_manager(tmp_path, sessions)

    async def fake_get(url, max_redirects=0):
        return _response(404, "not found")

    context = _fake_context(fake_get)
    pool = _pool_with_context(context)
    endpoints = [
        Endpoint(url=f"https://x/bank/showAccount?listAccounts=80000{i}", method="GET", endpoint_type="api", parameters=["listAccounts"])
        for i in range(6)
    ]
    module = IdorTestsModule(config=IdorTestConfig(candidate_ids=["1", "2"]))

    results = await module.run_techniques(endpoints, session_manager, pool)

    by_id = {r.technique_id: r for r in results if r.technique_id == "TC-053.6"}
    assert "TC-053.6" in by_id
    assert by_id["TC-053.6"].status == FAIL
