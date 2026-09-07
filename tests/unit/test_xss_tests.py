"""Unit tests for Layer 9 — stof.modules.xss_tests (TC-128)."""
import asyncio
import re
from unittest.mock import AsyncMock

import pytest

from stof.auth.base import AuthProvider
from stof.config.schema import UserConfig
from stof.crawler.endpoint_store import Endpoint
from stof.engine.multi_session import SessionPool
from stof.modules.results import FAIL, PASS, SKIPPED
from stof.modules.xss_tests import (
    XssTestConfig,
    XssTestsModule,
    _dom_injection_points,
    _is_hash_route_url,
    _url_with_hash_query,
    reflects_unencoded,
)
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


# ---------------------------------------------------------------------------
# DOM-sink injection points -- hash-routed SPA support (TC-128.5/.6/.8)
# ---------------------------------------------------------------------------


def test_is_hash_route_url_true_for_route_shaped_fragment():
    assert _is_hash_route_url("https://x/#/search") is True


def test_is_hash_route_url_false_for_plain_anchor():
    assert _is_hash_route_url("https://x/page#section") is False


def test_is_hash_route_url_false_with_no_fragment():
    assert _is_hash_route_url("https://x/page") is False


def test_url_with_hash_query_preserves_route_path():
    """Regression: the real bug found live against Juice Shop --
    `_url_with_hash` alone replaces the ENTIRE fragment with the raw
    payload, destroying the route path ('#/search' becomes just the
    payload), so the app falls back to its default view and the real
    vulnerable sink is never even reached. The query-only variant must
    keep the route path intact."""
    url = _url_with_hash_query("https://x/#/search", "q", "<svg onload=alert(1)>")
    assert url.startswith("https://x/#/search?")
    assert "q=%3Csvg" in url or "%3Csvg" in url  # url-encoded payload present as the q value


def test_url_with_hash_query_preserves_other_existing_hash_params():
    url = _url_with_hash_query("https://x/#/search?category=fruit", "q", "payload")
    assert "category=fruit" in url
    assert "q=payload" in url


def test_dom_injection_points_includes_hash_route_query_variant_for_hash_routed_endpoint():
    endpoint = Endpoint(url="https://x/#/search", method="GET", endpoint_type="page")
    points = _dom_injection_points(endpoint, "q", "payload")
    labels = [label for label, _ in points]
    assert "location.hash route query" in labels
    hash_query_url = next(url for label, url in points if label == "location.hash route query")
    assert hash_query_url.startswith("https://x/#/search?")


def test_dom_injection_points_omits_hash_route_query_variant_for_a_normal_endpoint():
    endpoint = Endpoint(url="https://x/rest/products/search", method="GET", endpoint_type="api")
    points = _dom_injection_points(endpoint, "q", "payload")
    labels = [label for label, _ in points]
    assert "location.hash route query" not in labels
    assert labels == ["location.hash", "location.search"]


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
    """No query/body parameter (TC-128.1-.3/.7/.9), no free-text POST
    field (TC-128.4), and no GET endpoint at all for TC-128.5/TC-128.6
    to navigate to (`method="POST"` here, deliberately, so their shared
    GET-endpoint requirement also has nothing to work with) -- every
    technique should SKIP."""
    endpoints = [Endpoint(url="https://x/", method="POST", endpoint_type="page")]
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = XssTestsModule()

    results = await module.run_techniques(endpoints, session_manager, pool)

    by_id = _by_id(results)
    assert len(by_id) == 9
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
    assert by_id["TC-128.1"].finding.severity == "Medium"  # cvss_score=6.1 -- the textbook reflected-XSS reference score, Medium per the CVSS v3.1 scale (4.0-6.9)
    # The marker itself (proof of this-run-only) shows up in the evidence.
    assert module._marker in by_id["TC-128.1"].finding.request_raw
    # Regression: this technique's own description says "response-
    # inspection signal only... never rendered in a real browser to
    # confirm actual script execution" -- the structured confidence
    # field must actually say so too, not silently default to
    # "confirmed" while the prose says otherwise.
    assert by_id["TC-128.1"].finding.confidence == "likely"


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
async def test_css_injection_technique_fails_when_marker_reflects_unencoded(tmp_path):
    """TC-128.7 reuses the same byte-for-byte unencoded oracle as the
    other context-breakout techniques -- reflecting the CSS-injection
    payload unencoded inside a style attribute should FAIL only
    TC-128.7, independent of TC-128.1-.3."""
    endpoint = Endpoint(url="https://x/theme", method="GET", endpoint_type="page", parameters=["color"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    module = XssTestsModule()
    css_payload = module._payload_for("TC-128.7")

    def fake_get(url, params=None, max_redirects=0):
        color = (params or {}).get("color", "")
        if color == css_payload:
            return _response(200, f'<html><body><div style="color:{color}"></div></body></html>')
        return _response(200, '<html><body><div style="color:blue"></div></body></html>')

    pool = _pool_with_context(_fake_context(get_side_effect=fake_get))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = _by_id(results)
    assert by_id["TC-128.7"].status == FAIL
    assert by_id["TC-128.7"].finding is not None
    assert by_id["TC-128.7"].finding.vuln_type == "CSS Injection"
    assert by_id["TC-128.1"].status == PASS
    assert by_id["TC-128.2"].status == PASS
    assert by_id["TC-128.3"].status == PASS


@pytest.mark.asyncio
async def test_html_injection_technique_fails_when_marker_reflects_unencoded_with_no_script_content(tmp_path):
    """TC-128.9 is deliberately payload-free of script/event-handler
    content -- a target that specifically strips `<script>` tags but
    still fails to HTML-encode output at all should FAIL this
    technique as a Medium "HTML Injection" finding, independent of
    (and with a lower severity than) the script-execution-shaped
    techniques."""
    endpoint = Endpoint(url="https://x/comment", method="GET", endpoint_type="page", parameters=["text"])
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    module = XssTestsModule()
    html_payload = module._payload_for("TC-128.9")

    def fake_get(url, params=None, max_redirects=0):
        text = (params or {}).get("text", "")
        if text == html_payload:
            return _response(200, f"<html><body><p>{text}</p></body></html>")
        return _response(200, "<html><body><p>clean</p></body></html>")

    pool = _pool_with_context(_fake_context(get_side_effect=fake_get))

    results = await module.run_techniques([endpoint], session_manager, pool)

    by_id = _by_id(results)
    assert by_id["TC-128.9"].status == FAIL
    assert by_id["TC-128.9"].finding is not None
    assert by_id["TC-128.9"].finding.vuln_type == "HTML Injection"
    assert by_id["TC-128.9"].finding.severity == "Medium"
    assert by_id["TC-128.9"].finding.cvss_score == 4.1
    assert "confirm()" not in by_id["TC-128.9"].finding.description
    assert by_id["TC-128.1"].status == PASS


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
    # Regression: same response-inspection-only gap as the reflected
    # technique above -- this technique's own description says "never
    # rendered in a real browser to confirm actual script execution".
    assert result.finding.confidence == "likely"


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
        self.url = "about:blank"

    def on(self, event, handler) -> None:
        if event == "dialog":
            self._dialog_handler = handler

    def remove_listener(self, event, handler) -> None:
        if event == "dialog" and self._dialog_handler is handler:
            self._dialog_handler = None

    async def goto(self, url: str, timeout: "int | None" = None) -> None:
        self.visited_urls.append(url)
        self.url = url  # normal navigation: `page.url` ends up where goto() was told to go
        if self._dialog_message is not None and self._dialog_handler is not None:
            await self._dialog_handler(_FakeDialog(self._dialog_message))

    async def close(self) -> None:
        self.closed = True


_DOM_REDIRECT_MARKER_RE = re.compile(r"https://stof-dom-redirect-[0-9a-f]+\.invalid/")


class _FakeRedirectPage(_FakePage):
    """Simulates a client-side sink: when `simulate_vulnerable_sink` is
    True, `goto()` extracts whatever `https://stof-dom-redirect-....
    invalid/` marker URL the technique injected into the requested
    URL's hash/query and sets `page.url` to it -- exactly what a real
    `location.href = location.hash.slice(1)`-shaped DOM sink would
    produce, without the test needing to know the technique's
    per-endpoint random marker in advance. `False` (the default)
    simulates a page with no such sink: `page.url` just stays at the
    requested URL, like ordinary navigation."""

    def __init__(self, simulate_vulnerable_sink: bool = False) -> None:
        super().__init__(dialog_message=None)
        self._simulate_vulnerable_sink = simulate_vulnerable_sink

    async def goto(self, url: str, timeout: "int | None" = None) -> None:
        self.visited_urls.append(url)
        match = _DOM_REDIRECT_MARKER_RE.search(url) if self._simulate_vulnerable_sink else None
        self.url = match.group(0) if match else url


class _FakeDomSinkPage(_FakePage):
    """Simulates TC-128.8's instrumentation: `add_init_script()` just
    records it was called (the real script's actual JS behavior is
    exercised by the real Playwright integration, not this unit test).
    `evaluate()` is the technique's own post-navigation sink-check call
    -- when `simulate_sink` is True, it extracts whatever marker string
    the technique placed in the last-visited URL's hash/query and
    returns one fake sink hit containing it, exactly the shape the real
    JS-side filter would return; `False` (default) returns no hits,
    simulating a page with no such sink."""

    def __init__(self, simulate_sink: bool = False) -> None:
        super().__init__(dialog_message=None)
        self._simulate_sink = simulate_sink
        self.init_scripts: list[str] = []

    async def add_init_script(self, script: str) -> None:
        self.init_scripts.append(script)

    async def evaluate(self, script: str, marker: str) -> list[dict]:
        if not self._simulate_sink:
            return []
        return [{"sink": "storage.setItem", "value": f"prefix-{marker}-suffix"}]


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
    # Contrast with the reflection/stored techniques' "likely" above:
    # this one navigated a REAL browser and observed a real triggered
    # dialog -- actual script execution, not a response-inspection
    # signal -- so staying at the "confirmed" default is correct.
    assert result.finding.confidence == "confirmed"


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


# ---------------------------------------------------------------------------
# TC-128.6: DOM-based Open Redirect
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dom_open_redirect_fails_when_browser_ends_up_at_marker_host(tmp_path):
    endpoint = Endpoint(url="https://x/welcome", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    module = XssTestsModule()
    page = _FakeRedirectPage(simulate_vulnerable_sink=True)
    pool = _pool_with_context(_context_with_page(page))

    result = await module._technique_dom_open_redirect([endpoint], session_manager, pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.vuln_type == "DOM-based Open Redirect"
    assert result.finding.severity == "Medium"
    # Fired on the very first probe (location.hash) -- only one
    # navigation should have happened before the technique returned.
    assert len(page.visited_urls) == 1
    assert "#" in page.visited_urls[0]


@pytest.mark.asyncio
async def test_dom_open_redirect_passes_when_browser_stays_on_origin(tmp_path):
    endpoint = Endpoint(url="https://x/welcome", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    module = XssTestsModule()
    page = _FakeRedirectPage(simulate_vulnerable_sink=False)
    pool = _pool_with_context(_context_with_page(page))

    result = await module._technique_dom_open_redirect([endpoint], session_manager, pool, evidence=None)

    assert result.status == PASS
    # Both injection points (location.hash, location.search) probed
    # for this one endpoint.
    assert len(page.visited_urls) == 2


@pytest.mark.asyncio
async def test_dom_open_redirect_skipped_when_no_get_endpoint_discovered(tmp_path):
    endpoints = [Endpoint(url="https://x/submit", method="POST", endpoint_type="form", parameters=["comment"])]
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = XssTestsModule()

    result = await module._technique_dom_open_redirect(endpoints, session_manager, pool, evidence=None)

    assert result.status == SKIPPED


@pytest.mark.asyncio
async def test_dom_open_redirect_page_is_closed_after_technique_runs(tmp_path):
    endpoint = Endpoint(url="https://x/welcome", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    module = XssTestsModule()
    page = _FakeRedirectPage(simulate_vulnerable_sink=False)
    pool = _pool_with_context(_context_with_page(page))

    await module._technique_dom_open_redirect([endpoint], session_manager, pool, evidence=None)

    assert page.closed is True


@pytest.mark.asyncio
async def test_navigate_and_check_redirect_backstop_bounds_a_goto_that_never_returns():
    """Same regression discipline as TC-128.5's own hang backstop test:
    a goto() that never returns must not block this technique forever."""

    class _HangingPage(_FakeRedirectPage):
        async def goto(self, url: str, timeout: "int | None" = None) -> None:
            await asyncio.sleep(3600)

    module = XssTestsModule()
    page = _HangingPage()

    redirected = await asyncio.wait_for(
        module._navigate_and_check_redirect(page, "https://x/welcome", "stof-dom-redirect-abc.invalid", timeout_ms=200),
        timeout=10,
    )

    assert redirected is False  # goto() never completed within the backstop -> treated as no redirect observed


@pytest.mark.asyncio
async def test_dom_open_redirect_role_not_configured_skips(tmp_path):
    endpoint = Endpoint(url="https://x/welcome", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = XssTestsModule()  # default low_priv_role="normal", not configured above

    result = await module._technique_dom_open_redirect([endpoint], session_manager, pool, evidence=None)

    assert result.status == SKIPPED
    assert "not configured" in result.detail


# ---------------------------------------------------------------------------
# TC-128.8: DOM Data Manipulation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dom_data_manipulation_fails_when_sink_records_marker(tmp_path):
    endpoint = Endpoint(url="https://x/welcome", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    module = XssTestsModule()
    page = _FakeDomSinkPage(simulate_sink=True)
    pool = _pool_with_context(_context_with_page(page))

    result = await module._technique_dom_data_manipulation([endpoint], session_manager, pool, evidence=None)

    assert result.status == FAIL
    assert result.finding is not None
    assert result.finding.vuln_type == "DOM Data Manipulation"
    assert result.finding.severity == "Medium"
    assert page.init_scripts  # instrumentation was actually installed
    # Fired on the very first probe (location.hash) -- only one
    # navigation should have happened before the technique returned.
    assert len(page.visited_urls) == 1


@pytest.mark.asyncio
async def test_dom_data_manipulation_passes_when_no_sink_records_marker(tmp_path):
    endpoint = Endpoint(url="https://x/welcome", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    module = XssTestsModule()
    page = _FakeDomSinkPage(simulate_sink=False)
    pool = _pool_with_context(_context_with_page(page))

    result = await module._technique_dom_data_manipulation([endpoint], session_manager, pool, evidence=None)

    assert result.status == PASS
    assert len(page.visited_urls) == 2  # both injection points probed


@pytest.mark.asyncio
async def test_dom_data_manipulation_skipped_when_no_get_endpoint_discovered(tmp_path):
    endpoints = [Endpoint(url="https://x/submit", method="POST", endpoint_type="form", parameters=["comment"])]
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = XssTestsModule()

    result = await module._technique_dom_data_manipulation(endpoints, session_manager, pool, evidence=None)

    assert result.status == SKIPPED


@pytest.mark.asyncio
async def test_dom_data_manipulation_page_is_closed_after_technique_runs(tmp_path):
    endpoint = Endpoint(url="https://x/welcome", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {"normal": Session(user_id="u", role="normal", auth_type="form_login")})
    module = XssTestsModule()
    page = _FakeDomSinkPage(simulate_sink=False)
    pool = _pool_with_context(_context_with_page(page))

    await module._technique_dom_data_manipulation([endpoint], session_manager, pool, evidence=None)

    assert page.closed is True


@pytest.mark.asyncio
async def test_dom_data_manipulation_role_not_configured_skips(tmp_path):
    endpoint = Endpoint(url="https://x/welcome", method="GET", endpoint_type="page")
    session_manager = _session_manager(tmp_path, {"admin": Session(user_id="a", role="admin", auth_type="form_login")})
    pool = _pool_with_context(_fake_context())
    module = XssTestsModule()  # default low_priv_role="normal", not configured above

    result = await module._technique_dom_data_manipulation([endpoint], session_manager, pool, evidence=None)

    assert result.status == SKIPPED
    assert "not configured" in result.detail
