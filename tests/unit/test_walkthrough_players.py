"""Unit tests for Layer 13 — stof.reporting.walkthrough_players.

Reuses this test suite's own `_FakePage` fake-Playwright-page
convention (see `test_xss_tests.py`'s `_FakePage`) rather than
`unittest.mock`, since `.on("dialog", handler)` must actually register a
callable `goto()` can invoke, and fill()/click() must actually be
recorded in call order for the new real-interaction players.
"""
from pathlib import Path

import pytest

from stof.crawler.endpoint_store import Endpoint
from stof.findings.models import Finding
from stof.reporting import walkthrough_players as wp


class _FakeDialog:
    def __init__(self, message: str) -> None:
        self.message = message
        self.dismissed = False

    async def dismiss(self) -> None:
        self.dismissed = True


class _FakeLocator:
    def __init__(self, page: "_FakePage", selector: str) -> None:
        self._page = page
        self._selector = selector

    async def count(self) -> int:
        return 1 if self._selector in self._page.present_selectors else 0

    async def fill(self, value: str, timeout: "int | None" = None) -> None:
        self._page.fills.append((self._selector, value))

    async def click(self, timeout: "int | None" = None, force: bool = False) -> None:
        self._page.clicks.append(self._selector)

    async def press(self, key: str) -> None:
        self._page.presses.append((self._selector, key))

    async def inner_text(self) -> str:
        if self._selector == "body":
            return self._page.body_text
        return ""


class _FakePage:
    """`present_selectors` controls which CSS selectors `_resolve_selector()`
    (and the generic form_login fallback lists) will "find" on this
    fake page -- defaults to the common username/password/submit
    candidates so every player under test has a real form to interact
    with, matching a genuine target page."""

    def __init__(
        self, dialog_message: "str | None" = None, present_selectors=None, url: str = "https://x/target",
        body_text: str = "Sign Off | My Account",
    ) -> None:
        self._dialog_message = dialog_message
        self._dialog_handler = None
        self.present_selectors = present_selectors if present_selectors is not None else {
            "input[type='email']", "input[type='password']", "button[type='submit']",
        }
        self.visited_urls: list[str] = []
        self.evaluated: list[tuple] = []
        self.fills: list[tuple[str, str]] = []
        self.clicks: list[str] = []
        self.presses: list[tuple[str, str]] = []
        self.url = url
        self.body_text = body_text

    def on(self, event, handler) -> None:
        if event == "dialog":
            self._dialog_handler = handler

    def locator(self, selector: str) -> _FakeLocator:
        return _FakeLocator(self, selector)

    async def goto(self, url: str, timeout: "int | None" = None) -> None:
        self.visited_urls.append(url)
        self.url = url
        if self._dialog_message is not None and self._dialog_handler is not None:
            await self._dialog_handler(_FakeDialog(self._dialog_message))

    async def fill(self, selector: str, value: str) -> None:
        self.fills.append((selector, value))

    async def click(self, selector: str, timeout: "int | None" = None, force: bool = False) -> None:
        self.clicks.append(selector)

    async def evaluate(self, script, *args) -> None:
        self.evaluated.append((script, args))

    async def wait_for_load_state(self, state: str = "load", timeout: "int | None" = None) -> None:
        pass

    async def screenshot(self, path: str, full_page: bool = True) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(b"\x89PNG\r\n\x1a\nfake")

    async def close(self) -> None:
        pass


class _FakeContext:
    def __init__(self, cookies=None) -> None:
        self._cookies = cookies or [{"name": "JSESSIONID", "value": "abc123"}]
        self.added_cookies: list = []
        self._new_page = None

    def set_next_page(self, page: "_FakePage") -> None:
        self._new_page = page

    async def new_page(self) -> "_FakePage":
        return self._new_page or _FakePage()

    async def cookies(self):
        return self._cookies

    async def add_cookies(self, cookies) -> None:
        self.added_cookies.extend(cookies)

    async def close(self) -> None:
        pass


class _FakeSessionPool:
    def __init__(self, anon_page: "_FakePage | None" = None) -> None:
        self.anon_context = _FakeContext()
        if anon_page is not None:
            self.anon_context.set_next_page(anon_page)

    async def new_anonymous_context(self) -> "_FakeContext":
        return self.anon_context


def _endpoint(url="https://x/target", method="GET") -> Endpoint:
    return Endpoint(url=url, method=method, endpoint_type="page")


def _finding(vuln_type: str, request_raw: str, response_raw: str = "resp", endpoint=None) -> Finding:
    return Finding(
        module_id="m", vuln_type=vuln_type, severity="High", cvss_score=7.0,
        endpoint=endpoint or _endpoint(), user_role="normal",
        request_raw=request_raw, response_raw=response_raw,
        description="desc", recommendation="fix",
    )


@pytest.mark.asyncio
async def test_login_form_injection_fills_and_clicks_real_form(tmp_path):
    # Matches sqli_tests.py's own real `request_preview` format for
    # TC-127.4: f"POST {url}\n{username_param}={user_payload!r}&{password_param}=***"
    finding = _finding(
        "SQL Injection", request_raw="POST https://x/login.jsp\nuid=\"' OR '1'='1\"&passw=***",
    )
    page = _FakePage()
    steps = await wp.play_login_form_injection(page, None, finding, "normal", None, None, tmp_path)

    assert len(steps) == 3
    assert page.visited_urls == ["https://x/login.jsp"]
    # the payload was genuinely typed into a real field, and the form was genuinely clicked
    assert ("input[type='email']", "' OR '1'='1") in page.fills
    assert page.clicks == ["button[type='submit']"]
    # two DIFFERENT screenshots -- the core bug being fixed (byte-identical before/after)
    assert steps[0].screenshot_path is not None
    assert steps[1].screenshot_path is not None
    assert steps[0].screenshot_path != steps[1].screenshot_path


@pytest.mark.asyncio
async def test_url_reflection_encodes_payload_and_navigates(tmp_path):
    finding = _finding(
        "Reflected Cross-Site Scripting",
        request_raw="GET https://x/search\nq='<svg onload=confirm(1)>'",
    )
    page = _FakePage()
    steps = await wp.play_url_reflection(page, None, finding, "normal", None, None, tmp_path)

    assert len(steps) == 2
    # URL-encoded -- fixes the blank-white-screenshot bug (raw '<'/'(' broke goto()'s URL parsing)
    assert "<" not in page.visited_urls[0]
    assert page.visited_urls[0].startswith("https://x/search?q=")
    assert steps[0].screenshot_path is not None


@pytest.mark.asyncio
async def test_dom_execution_captures_dialog_message(tmp_path):
    finding = _finding("DOM-based Cross-Site Scripting", request_raw="GET https://x/welcome#<svg onload=confirm(1)>")
    page = _FakePage(dialog_message="marker-xyz")
    steps = await wp.play_dom_execution(page, None, finding, "normal", None, None, tmp_path)

    assert len(steps) == 2
    assert steps[1].detail == "marker-xyz"
    assert "<" not in page.visited_urls[0]


@pytest.mark.asyncio
async def test_dom_execution_no_dialog_highlights_and_returns_steps(tmp_path):
    finding = _finding("DOM-based Cross-Site Scripting", request_raw="GET https://x/welcome\nq=payload", response_raw="")
    page = _FakePage(dialog_message=None)
    steps = await wp.play_dom_execution(page, None, finding, "normal", None, None, tmp_path)

    assert len(steps) == 2
    assert steps[1].detail is None
    # no dialog -- falls back to a visible in-page highlight via evaluate()
    assert len(page.evaluated) == 1


@pytest.mark.asyncio
async def test_stored_plant_and_view_fills_real_field_and_submits(tmp_path):
    finding = _finding(
        "Stored Cross-Site Scripting",
        request_raw="PLANT: POST https://x/comment\ncomment=payload\nVERIFY: GET https://x/admin/view",
    )
    page = _FakePage(present_selectors={"[name='comment']", "button[type='submit']"})
    steps = await wp.play_stored_plant_and_view(page, None, finding, "admin", None, None, tmp_path)

    assert len(steps) == 4
    assert page.visited_urls == ["https://x/comment", "https://x/admin/view"]
    assert ("[name='comment']", "payload") in page.fills
    assert page.clicks == ["button[type='submit']"]


@pytest.mark.asyncio
async def test_session_after_logout_three_shot_cookie_reuse(tmp_path):
    endpoint = _endpoint(url="https://x/account")
    finding = _finding(
        "Session Not Invalidated After Logout",
        request_raw="GET https://x/logout (reused cookie)",
        endpoint=endpoint,
    )
    page = _FakePage(present_selectors={"a:has-text('Logout')"})
    context = _FakeContext(cookies=[{"name": "JSESSIONID", "value": "pre-logout-value"}])
    replay_page = _FakePage()
    pool = _FakeSessionPool(anon_page=replay_page)

    steps = await wp.play_session_after_logout(page, context, finding, "normal", None, pool, tmp_path)

    assert len(steps) == 3
    assert page.visited_urls == ["https://x/account"]
    assert page.clicks == ["a:has-text('Logout')"]
    # the pre-logout cookie jar was captured and re-applied to a fresh, isolated context
    assert pool.anon_context.added_cookies == [{"name": "JSESSIONID", "value": "pre-logout-value"}]
    assert replay_page.visited_urls == ["https://x/account"]
    assert all(s.screenshot_path is not None for s in steps)
    assert "still serves it" in steps[2].caption


@pytest.mark.asyncio
async def test_session_after_logout_step3_honest_when_replay_looks_anonymous(tmp_path):
    """Regression test for a real bug found by manually inspecting live
    screenshots: a silently-swallowed `add_cookies()` failure (or a
    genuinely anonymous-looking replay) must never be presented as
    proof the vulnerability reproduced -- the step must say so
    honestly instead."""
    endpoint = _endpoint(url="https://x/account")
    finding = _finding("Session Not Invalidated After Logout", request_raw="GET https://x/logout", endpoint=endpoint)
    page = _FakePage(present_selectors={"a:has-text('Logout')"})
    context = _FakeContext(cookies=[{"name": "JSESSIONID", "value": "pre-logout-value"}])
    replay_page = _FakePage(body_text="Sign In | Online Banking Login")  # looks anonymous, not authenticated
    pool = _FakeSessionPool(anon_page=replay_page)

    steps = await wp.play_session_after_logout(page, context, finding, "normal", None, pool, tmp_path)

    assert len(steps) == 3
    assert "did not visually reproduce" in steps[2].caption
    assert "still serves it" not in steps[2].caption


@pytest.mark.asyncio
async def test_session_after_logout_step3_reports_cookie_reuse_failure(tmp_path):
    """A real `add_cookies()` exception must be surfaced in the step's
    detail, not silently swallowed into a misleading success caption."""

    class _FailingCookieContext(_FakeContext):
        async def add_cookies(self, cookies) -> None:
            raise RuntimeError("cookie rejected: unsupported field")

    endpoint = _endpoint(url="https://x/account")
    finding = _finding("Session Not Invalidated After Logout", request_raw="GET https://x/logout", endpoint=endpoint)
    page = _FakePage(present_selectors={"a:has-text('Logout')"})
    context = _FakeContext(cookies=[{"name": "JSESSIONID", "value": "pre-logout-value"}])
    pool = _FakeSessionPool()
    pool.anon_context = _FailingCookieContext(cookies=[{"name": "JSESSIONID", "value": "pre-logout-value"}])

    steps = await wp.play_session_after_logout(page, context, finding, "normal", None, pool, tmp_path)

    assert len(steps) == 3
    assert "Could not re-apply" in steps[2].caption
    assert "cookie rejected" in (steps[2].detail or "")


@pytest.mark.asyncio
async def test_no_rate_limit_submits_login_repeatedly(tmp_path):
    finding = _finding("No Rate Limiting on Login", request_raw="3x POST https://x/login.jsp (wrong creds)")
    page = _FakePage()
    steps = await wp.play_no_rate_limit(page, None, finding, "normal", None, None, tmp_path)

    assert page.visited_urls == ["https://x/login.jsp"]
    assert len(steps) == 2
    # 3 attempts recorded -- real fill+click each time, not a single navigation
    assert len(page.clicks) == 3
    assert len([f for f in page.fills if f[0] == "input[type='password']"]) == 3


@pytest.mark.asyncio
async def test_csrf_no_token_outlines_form_and_builds_data_url_poc(tmp_path):
    finding = _finding("Cross-Site Request Forgery (CSRF)", request_raw="POST https://x/transfer (fields: ['amount'])")
    page = _FakePage()
    steps = await wp.play_csrf_no_token(page, None, finding, "normal", None, None, tmp_path)

    assert page.visited_urls[0] == "https://x/transfer"
    # second navigation is a local, self-contained data: URL PoC -- never an external host
    assert page.visited_urls[1].startswith("data:text/html,")
    assert "amount" in page.visited_urls[1]
    assert len(page.evaluated) == 1  # the "no CSRF token" outline
    assert len(steps) == 3


@pytest.mark.asyncio
async def test_authenticated_navigation_uses_endpoint_url(tmp_path):
    endpoint = _endpoint(url="https://x/api/orders/123")
    finding = _finding("Insecure Direct Object Reference (IDOR)", request_raw="GET https://x/api/orders/123", endpoint=endpoint)
    page = _FakePage(url="https://x/api/orders/123")
    steps = await wp.play_authenticated_navigation(page, None, finding, "normal", None, None, tmp_path)

    assert page.visited_urls == ["https://x/api/orders/123"]
    assert len(steps) == 2
    assert "could not reproduce" not in steps[1].caption


@pytest.mark.asyncio
async def test_authenticated_navigation_honesty_check_on_login_redirect(tmp_path):
    """If the replay unexpectedly lands on a login page, the caption
    must say so honestly rather than presenting a misleading
    screenshot as proof -- the exact bug this rebuild fixes."""
    endpoint = _endpoint(url="https://x/api/orders/123")
    finding = _finding("Insecure Direct Object Reference (IDOR)", request_raw="GET https://x/api/orders/123", endpoint=endpoint)
    page = _FakePage(url="https://x/api/orders/123")

    async def _goto(url, timeout=None):
        page.visited_urls.append(url)
        page.url = "https://x/login"

    page.goto = _goto
    steps = await wp.play_authenticated_navigation(page, None, finding, "normal", None, None, tmp_path)

    assert len(steps) == 2
    assert "could not reproduce the authenticated state" in steps[1].caption


@pytest.mark.asyncio
async def test_annotated_evidence_pretty_prints_json(tmp_path):
    endpoint = _endpoint(url="https://x/api/info")
    finding = _finding("Sensitive Data Exposure", request_raw="GET https://x/api/info", response_raw='{"secret": "abc123"}', endpoint=endpoint)
    page = _FakePage()
    steps = await wp.play_annotated_evidence(page, None, finding, "normal", None, None, tmp_path)

    assert page.visited_urls == ["https://x/api/info"]
    assert len(page.evaluated) == 1
    assert page.evaluated[0][0] == wp._PRETTY_JSON_JS
    assert len(steps) == 1
    assert "pretty-printed" in steps[0].caption


@pytest.mark.asyncio
async def test_annotated_evidence_callout_for_non_json(tmp_path):
    endpoint = _endpoint(url="https://x/info")
    finding = _finding("Missing Security Header", request_raw="GET https://x/info", response_raw="X-Frame-Options missing", endpoint=endpoint)
    page = _FakePage()
    steps = await wp.play_annotated_evidence(page, None, finding, "normal", None, None, tmp_path)

    assert page.visited_urls == ["https://x/info"]
    assert len(page.evaluated) == 1
    assert page.evaluated[0][0] == wp._CALLOUT_JS
    assert len(steps) == 1
    assert steps[0].detail == "X-Frame-Options missing"


def test_players_registry_covers_every_classifier_category():
    from stof.reporting import walkthrough_classify as wc

    expected = {
        wc.LOGIN_FORM_INJECTION, wc.URL_REFLECTION, wc.DOM_EXECUTION,
        wc.STORED_PLANT_AND_VIEW, wc.SESSION_AFTER_LOGOUT, wc.NO_RATE_LIMIT,
        wc.CSRF_NO_TOKEN, wc.AUTHENTICATED_NAVIGATION, wc.ANNOTATED_EVIDENCE,
    }
    assert expected.issubset(set(wp.PLAYERS.keys()))
