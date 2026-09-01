"""Unit tests for Layer 9 — stof.modules.xss_tests (TC-128)."""
import asyncio
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthProvider
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.results import FAIL, PASS, SKIPPED
from stof.modules.xss_tests import XssTestConfig, XssTestsModule, reflects_unencoded
from stof.session.models import Session
from stof.session.session_manager import SessionManager
from stof.session.session_store import SessionStore

# ---------------------------------------------------------------------------
# reflects_unencoded() — pure function
# ---------------------------------------------------------------------------


def test_reflects_unencoded_true_for_verbatim_reflection():
    payload = "<svg onload=confirm('marker')>"
    body = f"<html><body>search results for {payload}</body></html>"
    assert reflects_unencoded(body, payload) is True


def test_reflects_unencoded_false_when_not_present():
    assert reflects_unencoded("<html>no reflection here</html>", "<svg onload=confirm('marker')>") is False


def test_reflects_unencoded_false_when_html_entity_encoded():
    """The application escaped the special characters -- the raw
    payload's literal `<`/`>` never appear, so this must NOT be
    reported as a hit (this is exactly the safe case)."""
    payload = "<svg onload=confirm('marker')>"
    encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
    body = f"<html><body>search results for {encoded}</body></html>"
    assert reflects_unencoded(body, payload) is False


def test_reflects_unencoded_false_inside_html_comment():
    """Reflected verbatim, but sitting inside an HTML comment -- inert,
    not executable, must not be reported as a hit."""
    payload = "<svg onload=confirm('marker')>"
    body = f"<html><!-- debug: {payload} --><body>ok</body></html>"
    assert reflects_unencoded(body, payload) is False


def test_reflects_unencoded_true_after_a_closed_comment():
    """A comment earlier in the document must not suppress a real,
    later, non-commented reflection."""
    payload = "<svg onload=confirm('marker')>"
    body = f"<html><!-- unrelated --><body>{payload}</body></html>"
    assert reflects_unencoded(body, payload) is True


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
    """No query/body parameter (TC-128.1-.3), no free-text POST field
    (TC-128.4), and no GET endpoint at all for TC-128.5 to navigate to
    (`method="POST"` here, deliberately, so TC-128.5's own GET-endpoint
    requirement also has nothing to work with) -- every technique
    should SKIP."""
    endpoints = [Endpoint(url="https://x/", method="POST", endpoint_type="page")]
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = XssTestsModule()

    results = await module.run_techniques(endpoints, session_manager, pool)

    by_id = _by_id(results)
    assert len(by_id) == 5
    assert all(r.status == SKIPPED for r in by_id.values())


@pytest.mark.asyncio
async def test_html_body_technique_fails_when_marker_reflects_unencoded(tmp_path):
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    module = XssTestsModule()
    payload = module._payload_for("TC-128.1")

    def fake_get(url, params=None, max_redirects=0):
        q = (params or {}).get("q", "")
        if q == payload:
            return _response(200, f"<html><body>results for {q}</body></html>")
        return _response(200, "<html><body>no results</body></html>")

    pool = _pool_with_context(_fake_context(get_side_effect=fake_get))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = _by_id(results)
    assert by_id["TC-128.1"].status == FAIL
    assert by_id["TC-128.1"].finding is not None
    assert by_id["TC-128.1"].finding.severity == "High"
    # The marker itself (proof of this-run-only) shows up in the evidence.
    assert module._marker in by_id["TC-128.1"].finding.request_raw


@pytest.mark.asyncio
async def test_html_body_technique_passes_when_response_html_encodes_the_payload(tmp_path):
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    module = XssTestsModule()

    def fake_get(url, params=None, max_redirects=0):
        q = (params or {}).get("q", "")
        encoded = q.replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#x27;").replace('"', "&quot;")
        return _response(200, f"<html><body>results for {encoded}</body></html>")

    pool = _pool_with_context(_fake_context(get_side_effect=fake_get))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = _by_id(results)
    assert by_id["TC-128.1"].status == PASS
    assert by_id["TC-128.2"].status == PASS
    assert by_id["TC-128.3"].status == PASS


@pytest.mark.asyncio
async def test_attribute_breakout_technique_fails_independently_of_html_body_technique(tmp_path):
    """Only the attribute-breakout payload reflects unencoded here (the
    other two contexts stay encoded) -- TC-128.2 should FAIL while
    TC-128.1/.3 stay clean, proving the three techniques are
    independently evaluated, not one bare marker check."""
    endpoint = Endpoint(url="https://x/profile", method="GET", endpoint_type="page", parameters=["name"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    module = XssTestsModule()
    attr_payload = module._payload_for("TC-128.2")

    def fake_get(url, params=None, max_redirects=0):
        name = (params or {}).get("name", "")
        if name == attr_payload:
            return _response(200, f'<html><body><input value="{name}"></body></html>')
        encoded = name.replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#x27;")
        return _response(200, f'<html><body><input value="{encoded}"></body></html>')

    pool = _pool_with_context(_fake_context(get_side_effect=fake_get))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = _by_id(results)
    assert by_id["TC-128.2"].status == FAIL
    assert by_id["TC-128.1"].status == PASS
    assert by_id["TC-128.3"].status == PASS


@pytest.mark.asyncio
async def test_role_not_configured_skips_every_technique(tmp_path):
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["q"])
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="u", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = XssTestsModule()  # default low_priv_role="normal", not configured above

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = _by_id(results)
    assert all(r.status == SKIPPED for r in by_id.values())
    assert "not configured" in by_id["TC-128.1"].detail


@pytest.mark.asyncio
async def test_marker_is_unique_per_module_instance():
    """Regression: the whole point of a per-run-random marker is that
    two different scan runs (two different module instances) never
    produce the same tagged payload."""
    first, second = XssTestsModule(), XssTestsModule()
    assert first._marker != second._marker


# ---------------------------------------------------------------------------
# TC-128.4 stored XSS (plant/verify) — mirrors sqli_tests.py's TC-127.6 tests
# ---------------------------------------------------------------------------


def _stored_xss_endpoints():
    plant = Endpoint(
        url="https://x/sendFeedback", method="POST", endpoint_type="form",
        parameters=["name", "email_addr", "subject", "comments"],
        param_locations={"name": "body", "email_addr": "body", "subject": "body", "comments": "body"},
    )
    verify = Endpoint(url="https://x/admin/admin.jsp", method="GET", endpoint_type="page")
    return [plant, verify]


@pytest.mark.asyncio
async def test_stored_xss_fails_when_plant_and_verify_both_succeed(tmp_path):
    endpoints = _stored_xss_endpoints()
    session_manager = _session_manager(tmp_path, {
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
    })
    module = XssTestsModule(config=XssTestConfig(allow_state_changing_probes=True))
    payload = module._payload_for("TC-128.4")

    def fake_post(url, form=None, max_redirects=0):
        return _response(200, "Thank you for your feedback")

    def fake_get(url, max_redirects=0):
        if "admin" in url:
            return _response(200, f"<html><body>submitted comment: {payload}</body></html>")
        return _response(200, "ok")

    context = _fake_context(get_side_effect=fake_get, post_side_effect=fake_post)
    pool = _pool_with_context(context)

    result = await module._technique_stored_xss(endpoints, session_manager, pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.vuln_type == "Stored Cross-Site Scripting"
    assert "sendFeedback" in result.finding.description
    assert "admin.jsp" in result.finding.description
    assert module._marker in result.finding.request_raw


@pytest.mark.asyncio
async def test_stored_xss_passes_when_verify_finds_no_unencoded_reflection(tmp_path):
    endpoints = _stored_xss_endpoints()
    session_manager = _session_manager(tmp_path, {
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
    })
    module = XssTestsModule(config=XssTestConfig(allow_state_changing_probes=True))
    payload = module._payload_for("TC-128.4")

    def fake_post(url, form=None, max_redirects=0):
        return _response(200, "Thank you for your feedback")

    def fake_get(url, max_redirects=0):
        if "admin" in url:
            encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
            return _response(200, f"<html><body>submitted comment: {encoded}</body></html>")
        return _response(200, "ok")

    context = _fake_context(get_side_effect=fake_get, post_side_effect=fake_post)
    pool = _pool_with_context(context)

    result = await module._technique_stored_xss(endpoints, session_manager, pool, evidence=None)

    assert result.status == PASS


@pytest.mark.asyncio
async def test_stored_xss_skipped_when_state_changing_probes_disabled(tmp_path):
    endpoints = _stored_xss_endpoints()
    session_manager = _session_manager(tmp_path, {
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
    })
    pool = _pool_with_context(_fake_context())
    module = XssTestsModule()  # allow_state_changing_probes defaults False

    result = await module._technique_stored_xss(endpoints, session_manager, pool, evidence=None)

    assert result.status == SKIPPED
    assert "allow_state_changing_probes" in result.detail


@pytest.mark.asyncio
async def test_stored_xss_skipped_when_no_free_text_field_discovered(tmp_path):
    endpoints = [Endpoint(url="https://x/admin/admin.jsp", method="GET", endpoint_type="page")]
    session_manager = _session_manager(tmp_path, {
        "normal": Session(user_id="u", role="normal", auth_type="form_login"),
        "admin": Session(user_id="a", role="admin", auth_type="form_login"),
    })
    pool = _pool_with_context(_fake_context())
    module = XssTestsModule(config=XssTestConfig(allow_state_changing_probes=True))

    result = await module._technique_stored_xss(endpoints, session_manager, pool, evidence=None)

    assert result.status == SKIPPED


# ---------------------------------------------------------------------------
# TC-128.5 DOM XSS (real in-browser execution confirmation)
# ---------------------------------------------------------------------------


class _FakeDialog:
    def __init__(self, message: str) -> None:
        self.message = message
        self.dismissed = False

    async def dismiss(self) -> None:
        self.dismissed = True


class _FakePage:
    """Minimal stand-in for a Playwright `Page`, following this test
    suite's own fake/mock convention (see `_fake_context`/`_response`
    above) rather than reaching for `unittest.mock` to simulate real
    event-listener semantics `AsyncMock` can't express: `.on("dialog",
    handler)` must actually register a callable `goto()` can invoke,
    which a bare `AsyncMock` attribute doesn't do."""

    def __init__(self, dialog_message: "str | None" = None) -> None:
        self._dialog_message = dialog_message
        self._dialog_handler = None
        self.visited_urls: list[str] = []
        self.closed = False

    def on(self, event, handler) -> None:
        if event == "dialog":
            self._dialog_handler = handler

    def remove_listener(self, event, handler) -> None:
        if event == "dialog" and self._dialog_handler is handler:
            self._dialog_handler = None

    async def goto(self, url: str, timeout: "int | None" = None) -> None:
        self.visited_urls.append(url)
        if self._dialog_message is not None and self._dialog_handler is not None:
            await self._dialog_handler(_FakeDialog(self._dialog_message))

    async def close(self) -> None:
        self.closed = True


def _context_with_page(page: "_FakePage"):
    context = _fake_context()
    context.new_page = AsyncMock(return_value=page)
    return context


@pytest.mark.asyncio
async def test_dom_xss_fails_when_dialog_fires_with_marker(tmp_path):
    endpoint = Endpoint(url="https://x/welcome", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    module = XssTestsModule()
    marker = module._marker
    page = _FakePage(dialog_message=f"pre-dialog-text {marker} post-dialog-text")
    pool = _pool_with_context(_context_with_page(page))

    result = await module._technique_dom_xss([endpoint], session_manager, pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.vuln_type == "DOM-based Cross-Site Scripting"
    assert marker in result.finding.description
    # Fired on the very first probe (location.hash) -- only one
    # navigation should have happened before the technique returned.
    assert len(page.visited_urls) == 1
    assert "#" in page.visited_urls[0]


@pytest.mark.asyncio
async def test_dom_xss_passes_when_no_dialog_fires(tmp_path):
    endpoint = Endpoint(url="https://x/welcome", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    module = XssTestsModule()
    page = _FakePage(dialog_message=None)
    pool = _pool_with_context(_context_with_page(page))

    result = await module._technique_dom_xss([endpoint], session_manager, pool, evidence=None)

    assert result.status == PASS
    # Both injection points (location.hash, location.search) probed
    # for this one endpoint.
    assert len(page.visited_urls) == 2


@pytest.mark.asyncio
async def test_dom_xss_passes_when_dialog_fires_without_marker(tmp_path):
    """A dialog unrelated to this run (e.g. a stale/unrelated page
    confirm()) must NOT be misreported as a hit -- only a dialog
    containing THIS run's own marker counts."""
    endpoint = Endpoint(url="https://x/welcome", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    module = XssTestsModule()
    page = _FakePage(dialog_message="some unrelated confirm() message")
    pool = _pool_with_context(_context_with_page(page))

    result = await module._technique_dom_xss([endpoint], session_manager, pool, evidence=None)

    assert result.status == PASS


@pytest.mark.asyncio
async def test_dom_xss_uses_discovered_query_parameter_name_for_search_injection(tmp_path):
    endpoint = Endpoint(url="https://x/search", method="GET", endpoint_type="page", parameters=["term"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    module = XssTestsModule()
    page = _FakePage(dialog_message=None)
    pool = _pool_with_context(_context_with_page(page))

    await module._technique_dom_xss([endpoint], session_manager, pool, evidence=None)

    search_url = page.visited_urls[1]
    assert "term=" in search_url


@pytest.mark.asyncio
async def test_dom_xss_skipped_when_no_get_endpoint_discovered(tmp_path):
    endpoints = [Endpoint(url="https://x/submit", method="POST", endpoint_type="form", parameters=["comment"])]
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = XssTestsModule()

    result = await module._technique_dom_xss(endpoints, session_manager, pool, evidence=None)

    assert result.status == SKIPPED


@pytest.mark.asyncio
async def test_dom_xss_page_is_closed_after_technique_runs(tmp_path):
    endpoint = Endpoint(url="https://x/welcome", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    module = XssTestsModule()
    page = _FakePage(dialog_message=None)
    pool = _pool_with_context(_context_with_page(page))

    await module._technique_dom_xss([endpoint], session_manager, pool, evidence=None)

    assert page.closed is True


@pytest.mark.asyncio
async def test_navigate_and_check_dialog_backstop_bounds_a_goto_that_never_returns():
    """Regression test for a real hang observed in this project: a
    `goto()` call that never returns or raises at all (Playwright's own
    internal timeout failing to fire, a real occurrence in this
    project's flaky sandbox) must not block `_navigate_and_check_dialog`
    forever -- its `asyncio.wait_for` backstop has to force it to give
    up within a bounded time regardless of what the underlying `goto()`
    call itself does."""

    class _HangingPage(_FakePage):
        async def goto(self, url: str, timeout: "int | None" = None) -> None:
            await asyncio.sleep(3600)  # never returns within any sane probe timeout

    module = XssTestsModule()
    page = _HangingPage(dialog_message=None)

    # `_navigate_and_check_dialog`'s own backstop is `(timeout_ms / 1000)
    # + 5` seconds regardless of `timeout_ms` -- the outer bound here
    # just has to be comfortably longer than that, not tight.
    message = await asyncio.wait_for(
        module._navigate_and_check_dialog(page, "https://x/welcome", timeout_ms=200), timeout=10,
    )

    assert message is None  # goto() "failed" (never completed within the backstop) -> no dialog observed


@pytest.mark.asyncio
async def test_dom_xss_role_not_configured_skips(tmp_path):
    endpoint = Endpoint(url="https://x/welcome", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = XssTestsModule()  # default low_priv_role="normal", not configured above

    result = await module._technique_dom_xss([endpoint], session_manager, pool, evidence=None)

    assert result.status == SKIPPED
    assert "not configured" in result.detail
