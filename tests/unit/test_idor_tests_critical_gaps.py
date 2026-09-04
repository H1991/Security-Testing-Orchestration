"""Unit tests for stof.modules.idor_tests' newest techniques: TC-053.3
(body-field IDOR), TC-054.4 (nested object reference), TC-055.4
(hidden endpoint discovery), TC-050.4 (client-side-only access
control), TC-052.3 (privilege-escalation chaining), TC-052.4 (mass
assignment) -- the last 6 of the 24 Critical-severity gaps this
project tracked in EXPLOIT_COVERAGE.md, closed after auditing which
ones Burp itself can't automate either."""
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthProvider
from stof.authorization.decision import AuthorizationDecision
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.findings.models import Finding
from stof.modules.idor_tests import IdorTestConfig, IdorTestsModule
from stof.modules.results import FAIL, PASS, SKIPPED
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


def _fake_context(**method_side_effects):
    context = AsyncMock()
    context.new_page = AsyncMock(return_value=AsyncMock())
    for method, side_effect in method_side_effects.items():
        setattr(context.request, method, AsyncMock(side_effect=side_effect))
    return context


def _pool_with_context(context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=context)
    return SessionPool(browser)


# ---------------------------------------------------------------------------
# TC-053.3 -- body-field IDOR
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_body_field_idor_skipped_by_default(tmp_path):
    endpoint = Endpoint(url="https://x/api/orders", method="POST", endpoint_type="api", parameters=["orderId"])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = IdorTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-053.3"].status == SKIPPED


@pytest.mark.asyncio
async def test_body_field_idor_fails_when_distinct_objects_returned(tmp_path):
    endpoint = Endpoint(url="https://x/api/orders", method="POST", endpoint_type="api", parameters=["orderId"])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    bodies = {"1": "Order #1 details" * 20, "2": "Order #2 details" * 20}

    async def fake_post(url, data=None, headers=None, max_redirects=0):
        import json
        payload = json.loads(data)
        cid = payload["orderId"]
        return _response(200, bodies[cid]) if cid in bodies else _response(404, "not found")

    pool = _pool_with_context(_fake_context(post=fake_post))
    config = IdorTestConfig(candidate_ids=["1", "2"], allow_state_changing_probes=True)
    module = IdorTestsModule(config=config)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-053.3"].status == FAIL
    assert by_id["TC-053.3"].finding is not None


# ---------------------------------------------------------------------------
# TC-053.5 -- HTTP method override (downgraded from an unconditional
# "GET returned 200" check after review feedback: a POST endpoint can
# legitimately also support GET, e.g. a REST collection that GET-lists
# and POST-creates -- that's normal design, not a bypass)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_method_override_fails_when_anon_denied_and_low_priv_allowed(tmp_path):
    endpoint = Endpoint(url="https://x/api/orders", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    normal_context = _fake_context(get=lambda url, max_redirects=0: _response(200, "order list contents" * 10))
    anon_context = _fake_context(get=lambda url, max_redirects=0: _response(403, "Forbidden"))
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=anon_context)
    pool = SessionPool(browser)
    pool._contexts["normal"] = normal_context
    module = IdorTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-053.5"].status == FAIL
    assert by_id["TC-053.5"].finding.severity == "Medium"
    assert "response-code differential" in by_id["TC-053.5"].finding.description


@pytest.mark.asyncio
async def test_method_override_passes_when_anonymous_can_also_reach_get(tmp_path):
    """The exact false-positive a reviewer flagged: a route that
    legitimately answers GET for anyone (never protected at all) must
    not be reported just because it was discovered as a POST
    endpoint."""
    endpoint = Endpoint(url="https://x/api/orders", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    body = "order list contents" * 10

    normal_context = _fake_context(get=lambda url, max_redirects=0: _response(200, body))
    anon_context = _fake_context(get=lambda url, max_redirects=0: _response(200, body))
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=anon_context)
    pool = SessionPool(browser)
    pool._contexts["normal"] = normal_context
    module = IdorTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-053.5"].status == PASS


@pytest.mark.asyncio
async def test_method_override_passes_when_low_priv_get_is_denied(tmp_path):
    endpoint = Endpoint(url="https://x/api/orders", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    normal_context = _fake_context(get=lambda url, max_redirects=0: _response(403, "Forbidden"))
    anon_context = _fake_context(get=lambda url, max_redirects=0: _response(403, "Forbidden"))
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=anon_context)
    pool = SessionPool(browser)
    pool._contexts["normal"] = normal_context
    module = IdorTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-053.5"].status == PASS


# ---------------------------------------------------------------------------
# TC-054.4 -- nested object reference
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nested_object_reference_skipped_without_two_id_segments(tmp_path):
    endpoint = Endpoint(url="https://x/api/orders/5", method="GET", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = IdorTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-054.4"].status == SKIPPED


@pytest.mark.asyncio
async def test_nested_object_reference_fails_when_outer_segment_exposes_other_objects(tmp_path):
    endpoint = Endpoint(url="https://x/api/users/5/orders/12", method="GET", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    bodies = {"1": "User 1's orders" * 20, "2": "User 2's orders" * 20}

    async def fake_get(url, max_redirects=0):
        for cid, body in bodies.items():
            if f"/users/{cid}/" in url:
                return _response(200, body)
        return _response(404, "not found")

    pool = _pool_with_context(_fake_context(get=fake_get))
    config = IdorTestConfig(candidate_ids=["1", "2"])
    module = IdorTestsModule(config=config)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-054.4"].status == FAIL


# ---------------------------------------------------------------------------
# TC-055.4 -- hidden endpoint discovery
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hidden_endpoint_discovery_fails_on_reachable_wordlist_path(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    async def fake_get(url, max_redirects=0):
        if url.endswith("/actuator/env"):
            return _response(200, "spring boot env dump" * 20)
        return _response(404, "not found")

    pool = _pool_with_context(_fake_context(get=fake_get))
    module = IdorTestsModule(target_url="https://x/")

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-055.4"].status == FAIL


@pytest.mark.asyncio
async def test_hidden_endpoint_discovery_passes_when_nothing_reachable(tmp_path):
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context(get=lambda url, max_redirects=0: _response(404, "not found")))
    module = IdorTestsModule(target_url="https://x/")

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-055.4"].status == PASS


@pytest.mark.asyncio
async def test_hidden_endpoint_discovery_passes_on_spa_catchall_that_serves_200_for_any_path(tmp_path):
    """A client-side-routed SPA serves an identical index.html shell --
    HTTP 200, same bytes -- for ANY unmatched path, including every
    wordlist candidate AND the technique's own random control probe.
    Without a baseline comparison this would look like every hidden path
    is "reachable"; with it, PASS is correct."""
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context(get=lambda url, max_redirects=0: _response(200, "<html>spa shell</html>" * 20)))
    module = IdorTestsModule(target_url="https://x/")

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-055.4"].status == PASS


# ---------------------------------------------------------------------------
# TC-055.5 -- role-differential access matrix (complements TC-055.1's
# URL-name heuristic with a direct anonymous/low-priv/high-priv
# response comparison, per the external review's BFLA critique)
# ---------------------------------------------------------------------------


def _pool_with_role_contexts(contexts: dict[str, object], anon_context) -> SessionPool:
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=anon_context)
    pool = SessionPool(browser)
    for role, context in contexts.items():
        pool._contexts[role] = context
    return pool


@pytest.mark.asyncio
async def test_role_differential_access_fails_when_anon_denied_and_both_roles_match(tmp_path):
    """A non-obviously-privileged endpoint (doesn't match
    `privileged_path_hints`, so TC-055.1 never looks at it) that
    requires *some* authentication but returns identical content to
    both a low- and a high-privilege session has no real function-level
    authorization at all."""
    endpoint = Endpoint(url="https://x/api/orders/45", method="GET", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
    })
    body = "Order #45 full details, including another user's data" * 5

    async def admin_get(url, max_redirects=0):
        return _response(200, body)

    async def normal_get(url, max_redirects=0):
        return _response(200, body)

    async def anon_get(url, max_redirects=0):
        return _response(403, "Forbidden")

    admin_context = _fake_context(get=admin_get)
    normal_context = _fake_context(get=normal_get)
    anon_context = _fake_context(get=anon_get)
    pool = _pool_with_role_contexts({"admin": admin_context, "normal": normal_context}, anon_context)
    module = IdorTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-055.5"].status == FAIL
    assert by_id["TC-055.5"].finding is not None
    assert "byte-identical" in by_id["TC-055.5"].finding.description


@pytest.mark.asyncio
async def test_role_differential_access_passes_when_low_priv_role_is_denied(tmp_path):
    """The other half: a low-priv role correctly denied while the
    high-priv role succeeds is real, working authorization -- must not
    be flagged."""
    endpoint = Endpoint(url="https://x/api/orders/45", method="GET", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
    })

    async def admin_get(url, max_redirects=0):
        return _response(200, "Order #45 full details" * 10)

    async def normal_get(url, max_redirects=0):
        return _response(403, "Forbidden")

    async def anon_get(url, max_redirects=0):
        return _response(403, "Forbidden")

    admin_context = _fake_context(get=admin_get)
    normal_context = _fake_context(get=normal_get)
    anon_context = _fake_context(get=anon_get)
    pool = _pool_with_role_contexts({"admin": admin_context, "normal": normal_context}, anon_context)
    module = IdorTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-055.5"].status == PASS


@pytest.mark.asyncio
async def test_role_differential_access_passes_when_endpoint_is_public(tmp_path):
    """An endpoint reachable anonymously is out of scope for this
    technique entirely -- there's no authorization boundary to test."""
    endpoint = Endpoint(url="https://x/api/orders/45", method="GET", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
    })
    body = "public order confirmation page" * 10

    admin_context = _fake_context(get=lambda url, max_redirects=0: _response(200, body))
    normal_context = _fake_context(get=lambda url, max_redirects=0: _response(200, body))
    anon_context = _fake_context(get=lambda url, max_redirects=0: _response(200, body))
    pool = _pool_with_role_contexts({"admin": admin_context, "normal": normal_context}, anon_context)
    module = IdorTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-055.5"].status == PASS


@pytest.mark.asyncio
async def test_role_differential_access_skipped_when_no_candidate_endpoints(tmp_path):
    """Only privileged-looking URLs discovered (already fully covered by
    TC-055.1) leaves nothing for this technique to matrix-test."""
    endpoint = Endpoint(url="https://x/admin/admin.jsp", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
    })
    admin_context = _fake_context(get=lambda url, max_redirects=0: _response(200, "admin panel" * 20))
    normal_context = _fake_context(get=lambda url, max_redirects=0: _response(200, "admin panel" * 20))
    anon_context = _fake_context(get=lambda url, max_redirects=0: _response(403, "Forbidden"))
    pool = _pool_with_role_contexts({"admin": admin_context, "normal": normal_context}, anon_context)
    module = IdorTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-055.5"].status == SKIPPED


@pytest.mark.asyncio
async def test_role_differential_access_skipped_when_only_one_account_configured(tmp_path):
    """Single-account target (low_priv_role == high_priv_role): this
    technique's whole signal is "two DIFFERENT roles saw the same
    response," which is meaningless -- and, worse, a guaranteed false
    positive if run anyway, since a lone account's session probed twice
    is trivially byte-identical to itself. Must SKIP honestly, never
    report a fabricated PASS ("no gap found") or FAIL."""
    endpoint = Endpoint(url="https://x/api/orders/45", method="GET", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
    })
    body = "Order #45 full details" * 10

    normal_context = _fake_context(get=lambda url, max_redirects=0: _response(200, body))
    anon_context = _fake_context(get=lambda url, max_redirects=0: _response(403, "Forbidden"))
    pool = _pool_with_role_contexts({"normal": normal_context}, anon_context)
    module = IdorTestsModule(high_priv_role="normal", low_priv_role="normal")

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-055.5"].status == SKIPPED
    assert "one account" in by_id["TC-055.5"].detail or "only one account" in by_id["TC-055.5"].detail


# ---------------------------------------------------------------------------
# AuthorizationMatrix wiring -- TC-055.1, TC-055.5, and TC-053.5 all record
# what they observe into the same `module.authorization_matrix` instead of
# keeping private pass/fail bookkeeping (per the external review: "you now
# have two authorization architectures living in the repository," pointing
# at the then-unused stof/authorization/ package).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_role_differential_access_records_all_three_identities_into_the_matrix(tmp_path):
    endpoint = Endpoint(url="https://x/api/orders/45", method="GET", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
    })
    body = "Order #45 full details, including another user's data" * 5

    admin_context = _fake_context(get=lambda url, max_redirects=0: _response(200, body))
    normal_context = _fake_context(get=lambda url, max_redirects=0: _response(200, body))
    anon_context = _fake_context(get=lambda url, max_redirects=0: _response(403, "Forbidden"))
    pool = _pool_with_role_contexts({"admin": admin_context, "normal": normal_context}, anon_context)
    module = IdorTestsModule()

    await module.run_techniques([endpoint], session_manager, pool)

    assert module.authorization_matrix.decision_for(endpoint, "admin") == AuthorizationDecision.ALLOWED
    assert module.authorization_matrix.decision_for(endpoint, "normal") == AuthorizationDecision.ALLOWED
    assert module.authorization_matrix.decision_for(endpoint, "anonymous") == AuthorizationDecision.DENIED
    assert module.authorization_matrix.has_boundary(endpoint) is True


@pytest.mark.asyncio
async def test_vertical_privilege_escalation_records_low_priv_decision_into_the_matrix(tmp_path):
    endpoint = Endpoint(url="https://x/admin/admin.jsp", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
    })
    pool = _pool_with_context(_fake_context(get=lambda url, max_redirects=0: _response(200, "admin panel" * 20)))
    module = IdorTestsModule()

    await module.run_techniques([endpoint], session_manager, pool)

    assert module.authorization_matrix.decision_for(endpoint, "normal") == AuthorizationDecision.ALLOWED


@pytest.mark.asyncio
async def test_method_override_records_decisions_into_the_matrix(tmp_path):
    endpoint = Endpoint(url="https://x/api/orders", method="POST", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    normal_context = _fake_context(get=lambda url, max_redirects=0: _response(200, "order list contents" * 10))
    anon_context = _fake_context(get=lambda url, max_redirects=0: _response(403, "Forbidden"))
    browser = AsyncMock()
    browser.new_context = AsyncMock(return_value=anon_context)
    pool = SessionPool(browser)
    pool._contexts["normal"] = normal_context
    module = IdorTestsModule()

    await module.run_techniques([endpoint], session_manager, pool)

    assert module.authorization_matrix.decision_for(endpoint, "normal") == AuthorizationDecision.ALLOWED
    assert module.authorization_matrix.decision_for(endpoint, "anonymous") == AuthorizationDecision.DENIED


# ---------------------------------------------------------------------------
# TC-050.4 -- client-side-only access control
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_side_only_access_control_skips_when_dom_extraction_fails(tmp_path):
    """`_authenticated_context()`'s own `new_page()` call must succeed
    (it never navigates) -- only the DOM-extraction page's `.goto()`
    fails, exercising `_visible_nav_links()`'s own error handling."""
    session_manager = _session_manager(tmp_path, {
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
    })
    context = _fake_context()
    page_mock = AsyncMock()
    page_mock.goto = AsyncMock(side_effect=Exception("navigation failed in this test"))
    context.new_page = AsyncMock(return_value=page_mock)
    pool = _pool_with_context(context)
    module = IdorTestsModule()

    results = await module.run_techniques([], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-050.4"].status == SKIPPED


# ---------------------------------------------------------------------------
# TC-052.3 -- privilege-escalation chaining (pure sync method)
# ---------------------------------------------------------------------------


def _finding(vuln_type: str, response_raw: str) -> Finding:
    endpoint = Endpoint(url="https://x/api/users/2", method="GET", endpoint_type="api")
    return Finding(
        module_id="idor_tests", vuln_type=vuln_type, severity="Critical", cvss_score=8.1,
        endpoint=endpoint, user_role="admin", request_raw="GET x", response_raw=response_raw,
        description="d", recommendation="r",
    )


def test_privilege_escalation_chaining_fails_when_idor_body_has_privilege_field():
    module = IdorTestsModule()
    idor_finding = _finding("Insecure Direct Object Reference (IDOR)", '{"id": 2, "role": "admin", "email": "x@x.com"}')

    result = module._technique_privilege_escalation_chaining([idor_finding])

    assert result.status == FAIL
    assert result.finding is idor_finding


def test_privilege_escalation_chaining_passes_when_no_privilege_field():
    module = IdorTestsModule()
    idor_finding = _finding("Insecure Direct Object Reference (IDOR)", '{"id": 2, "name": "Widget"}')

    result = module._technique_privilege_escalation_chaining([idor_finding])

    assert result.status == PASS


def test_privilege_escalation_chaining_skipped_when_no_idor_findings():
    module = IdorTestsModule()

    result = module._technique_privilege_escalation_chaining([])

    assert result.status == SKIPPED


# ---------------------------------------------------------------------------
# TC-052.4 -- mass assignment
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mass_assignment_skipped_by_default(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="PUT", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = IdorTestsModule()

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-052.4"].status == SKIPPED


@pytest.mark.asyncio
async def test_mass_assignment_fails_when_role_field_echoed_back(tmp_path):
    endpoint = Endpoint(url="https://x/api/profile", method="PUT", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    context = _fake_context(put=lambda url, data=None, headers=None, max_redirects=0: _response(200, '{"role":"admin","isAdmin":true}'))
    pool = _pool_with_context(context)
    config = IdorTestConfig(allow_state_changing_probes=True)
    module = IdorTestsModule(config=config)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-052.4"].status == FAIL
    assert by_id["TC-052.4"].finding is not None


# ---------------------------------------------------------------------------
# TC-054.2/.3/.5 -- BOLA write-verb confirmation (read-back re-verification,
# not just the write's own status code -- see idor_knowledge_base.json's
# action_level_object family: "a write's HTTP status is never sufficient
# evidence by itself").
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bola_delete_confirmed_fail_when_object_genuinely_gone(tmp_path):
    """DELETE returns 204 for two candidate ids AND a follow-up GET on
    each shows the object is genuinely gone (404) -- this IS confirmed
    evidence and must FAIL."""
    endpoint = Endpoint(url="https://x/api/orders", method="DELETE", endpoint_type="api", parameters=["orderId"])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_delete(url, **kwargs):
        return _response(204, "")

    async def fake_get(url, **kwargs):
        # Every follow-up GET (regardless of candidate) finds the object gone.
        return _response(404, "not found")

    context = _fake_context(delete=fake_delete, get=fake_get)
    pool = _pool_with_context(context)
    config = IdorTestConfig(candidate_ids=["1", "2"], allow_state_changing_probes=True)
    module = IdorTestsModule(config=config)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-054.3"].status == FAIL
    assert by_id["TC-054.3"].finding is not None
    assert "absent" in by_id["TC-054.3"].finding.description.lower()


@pytest.mark.asyncio
async def test_bola_delete_not_confirmed_when_object_still_gettable_afterward(tmp_path):
    """DELETE returns 204 for two candidate ids (the old, weaker check
    would have reported this as FAIL) but a follow-up GET shows the
    object still exists and is fully readable -- this must NOT be
    reported as a confirmed cross-object write."""
    endpoint = Endpoint(url="https://x/api/orders", method="DELETE", endpoint_type="api", parameters=["orderId"])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_delete(url, **kwargs):
        return _response(204, "")

    async def fake_get(url, **kwargs):
        # The "deleted" object is still fully readable -- a no-op delete.
        return _response(200, "Order details still here" * 20)

    context = _fake_context(delete=fake_delete, get=fake_get)
    pool = _pool_with_context(context)
    config = IdorTestConfig(candidate_ids=["1", "2"], allow_state_changing_probes=True)
    module = IdorTestsModule(config=config)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-054.3"].status == PASS
    assert by_id["TC-054.3"].finding is None


@pytest.mark.asyncio
async def test_bola_patch_confirmed_fail_when_marker_reflected_on_readback(tmp_path):
    """PATCH returns 200 for two candidate ids AND the follow-up GET's
    body reflects the write's own unique marker value for both -- this
    IS confirmed evidence the write persisted against each object."""
    endpoint = Endpoint(url="https://x/api/orders", method="PATCH", endpoint_type="api", parameters=["orderId"])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    written_markers: dict[str, str] = {}

    async def fake_patch(url, data=None, headers=None, max_redirects=0):
        for part in data.split("&"):
            if part.startswith("stof_probe="):
                # keyed by the orderId query param on the URL
                from urllib.parse import parse_qs, urlsplit
                cid = parse_qs(urlsplit(url).query)["orderId"][0]
                written_markers[cid] = part.split("=", 1)[1]
        return _response(200, "")

    async def fake_get(url, **kwargs):
        from urllib.parse import parse_qs, urlsplit
        cid = parse_qs(urlsplit(url).query)["orderId"][0]
        marker = written_markers.get(cid, "")
        return _response(200, f"Order {cid} contents, probe={marker}" * 5)

    context = _fake_context(patch=fake_patch, get=fake_get)
    pool = _pool_with_context(context)
    config = IdorTestConfig(candidate_ids=["1", "2"], allow_state_changing_probes=True)
    module = IdorTestsModule(config=config)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-054.5"].status == FAIL
    assert by_id["TC-054.5"].finding is not None
    assert "marker" in by_id["TC-054.5"].finding.description.lower()


@pytest.mark.asyncio
async def test_bola_put_not_confirmed_when_marker_never_reflected(tmp_path):
    """PUT returns 200 for two candidate ids (the old, weaker check
    would have reported this as FAIL) but the follow-up GET never
    reflects the write's marker -- the write's own status code alone
    is not sufficient evidence, so this must PASS."""
    endpoint = Endpoint(url="https://x/api/orders", method="PUT", endpoint_type="api", parameters=["orderId"])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})

    async def fake_put(url, data=None, headers=None, max_redirects=0):
        return _response(200, "")

    async def fake_get(url, **kwargs):
        # Unrelated content -- never echoes back any write marker.
        return _response(200, "unrelated static content" * 10)

    context = _fake_context(put=fake_put, get=fake_get)
    pool = _pool_with_context(context)
    config = IdorTestConfig(candidate_ids=["1", "2"], allow_state_changing_probes=True)
    module = IdorTestsModule(config=config)

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results}
    assert by_id["TC-054.2"].status == PASS
    assert by_id["TC-054.2"].finding is None


@pytest.mark.asyncio
async def test_bfla_state_changing_tests_plainly_named_write_endpoint(tmp_path):
    """Regression: a real target's write endpoints were plainly named
    (no "admin"/"manage"/etc. anywhere in the URL, e.g.
    "/api/delete-category") yet had zero independent server-side
    authorization -- a low-privileged session could call them directly
    and the server accepted it. TC-055.2 used to require the URL match
    `_looks_privileged()`'s naming heuristic before even attempting the
    probe, silently skipping exactly this class of app."""
    endpoint = Endpoint(url="https://x/api/delete-category", method="DELETE", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    normal_context = _fake_context(delete=lambda url, max_redirects=0: _response(200, "ok"))
    browser = AsyncMock()
    pool = SessionPool(browser)
    pool._contexts["normal"] = normal_context
    module = IdorTestsModule(config=IdorTestConfig(allow_state_changing_probes=True))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results if r.technique_id == "TC-055.2"}
    assert by_id["TC-055.2"].status == FAIL
    assert by_id["TC-055.2"].finding.severity == "Critical"
    assert "delete-category" in by_id["TC-055.2"].finding.description


@pytest.mark.asyncio
async def test_bfla_state_changing_still_finds_nothing_when_server_denies(tmp_path):
    """Companion to the regression above: widening the candidate set
    must not turn every discovered write endpoint into a false
    positive -- a server that correctly denies the low-priv call still
    reports PASS."""
    endpoint = Endpoint(url="https://x/api/delete-category", method="DELETE", endpoint_type="api")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})

    normal_context = _fake_context(delete=lambda url, max_redirects=0: _response(403, "Forbidden"))
    browser = AsyncMock()
    pool = SessionPool(browser)
    pool._contexts["normal"] = normal_context
    module = IdorTestsModule(config=IdorTestConfig(allow_state_changing_probes=True))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = {r.technique_id: r for r in results if r.technique_id == "TC-055.2"}
    assert by_id["TC-055.2"].status == PASS
