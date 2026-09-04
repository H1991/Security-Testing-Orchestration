"""Unit tests for Layer 7 — stof.crawler.crawler.

Uses a tiny in-memory fake "site" (url -> links/forms/api-calls) instead
of mocking Playwright call-by-call: the crawler makes multiple
`page.evaluate()` calls per page (forms, then links) and multiple
`page.goto()` calls across the BFS, so a script/URL-aware fake is far
more reliable here than juggling AsyncMock `side_effect` ordering.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from stof.crawler.crawler import CrawlerConfig, crawl, verify_auth_required
from stof.crawler.endpoint_store import Endpoint


class _FakeCandidate:
    """One clickable-element candidate for `.locator(...).nth(i)` --
    backs `_discover_clickable_routes()`'s own locator calls."""

    def __init__(self, page: "FakePage", spec: dict):
        self._page = page
        self._spec = spec

    async def is_visible(self, timeout: int | None = None) -> bool:
        return self._spec.get("visible", True)

    async def inner_text(self, timeout: int | None = None) -> str:
        return self._spec.get("text", "")

    async def get_attribute(self, name: str):
        return self._spec.get(name)

    async def click(self, timeout: int | None = None, force: bool = False) -> None:
        if self._spec.get("click_error") and not (force and self._spec.get("force_click_succeeds")):
            raise RuntimeError("click failed")
        for handler in list(self._page._dialog_listeners):
            message = self._spec.get("dialog_message")
            if message:
                await handler(SimpleNamespace(message=message, dismiss=self._page._dismiss_dialog))
        # Simulates a menu/dropdown trigger: clicking this candidate
        # flips other candidates (by index into the same "clickable"
        # list) from invisible to visible, the same shape Juice Shop's
        # own "Account" button reveals a "Login" menu item.
        for revealed_index in self._spec.get("reveals", []):
            self._page._site[self._page.url]["clickable"][revealed_index]["visible"] = True
        leads_to = self._spec.get("leads_to")
        if leads_to is not None:
            self._page.url = leads_to


class _FakeLocator:
    def __init__(self, page: "FakePage", candidates: list[dict]):
        self._page = page
        self._candidates = candidates

    async def count(self) -> int:
        return len(self._candidates)

    def nth(self, index: int) -> _FakeCandidate:
        return _FakeCandidate(self._page, self._candidates[index])


class FakePage:
    def __init__(self, site: dict[str, dict]):
        self._site = site
        self.url = ""
        self.goto_calls: list[str] = []
        self.wait_for_load_state_calls: list[str] = []
        self._fail_remaining = {url: page.get("fail_times", 0) for url, page in site.items()}
        self._evaluate_fail_remaining = {
            url: page.get("evaluate_fail_times", 0) for url, page in site.items()
        }
        self._request_listeners: list = []
        self._response_listeners: list = []
        self._dialog_listeners: list = []

    async def _dismiss_dialog(self) -> None:
        pass

    async def goto(self, url: str, timeout: int | None = None) -> None:
        self.goto_calls.append(url)
        if url not in self._site:
            raise RuntimeError(f"404 Not Found: {url}")
        if self._site[url].get("hang"):
            # Simulates a wedged CDP connection where `page.goto()`'s
            # own `timeout` never fires at all -- live-observed against
            # a real target (see CrawlerConfig.page_watchdog_s). Never
            # resolves on its own; only the watchdog's asyncio.wait_for
            # can end this.
            await asyncio.Event().wait()
        if self._fail_remaining.get(url, 0) > 0:
            self._fail_remaining[url] -= 1
            raise RuntimeError(f"transient failure loading {url}")
        self.url = self._site[url].get("redirect_to", url)
        for handler in list(self._request_listeners):
            for req in self._site[url].get("api_calls", []):
                handler(req)
        for handler in list(self._response_listeners):
            page_response = self._site[url].get("response")
            if page_response is not None:
                handler(page_response)

    async def evaluate(self, script: str):
        page = self._site.get(self.url, {})
        if page.get("evaluate_error"):
            raise RuntimeError("Execution context was destroyed, most likely because of a navigation")
        if self._evaluate_fail_remaining.get(self.url, 0) > 0:
            self._evaluate_fail_remaining[self.url] -= 1
            raise RuntimeError("Execution context was destroyed, most likely because of a navigation")
        if "a[href]" in script:
            return page.get("links", [])
        return page.get("forms", [])

    def on(self, event: str, handler) -> None:
        if event == "request":
            self._request_listeners.append(handler)
        elif event == "response":
            self._response_listeners.append(handler)
        elif event == "dialog":
            self._dialog_listeners.append(handler)

    def remove_listener(self, event: str, handler) -> None:
        if event == "request" and handler in self._request_listeners:
            self._request_listeners.remove(handler)
        elif event == "response" and handler in self._response_listeners:
            self._response_listeners.remove(handler)
        elif event == "dialog" and handler in self._dialog_listeners:
            self._dialog_listeners.remove(handler)

    def locator(self, selector: str) -> _FakeLocator:
        page = self._site.get(self.url, {})
        return _FakeLocator(self, page.get("clickable", []))

    async def wait_for_load_state(self, state: str, timeout: int | None = None) -> None:
        self.wait_for_load_state_calls.append(self.url)
        page = self._site.get(self.url, {})
        if page.get("networkidle_hang"):
            await asyncio.Event().wait()

    async def wait_for_timeout(self, timeout: int) -> None:
        pass

    async def close(self) -> None:
        pass


class FakeContext:
    """The main BFS page (`self.page`, what most tests assert against)
    is a distinct object from any probe pages `crawl()` opens (form-
    submission probing, click-based navigation discovery) -- matching
    real Playwright, where `context.new_page()` always returns a new
    `Page`. Probe pages still read/mutate the same underlying `site`
    dict, so a click's `leads_to` is visible to the main page's own
    later `goto()` of that URL."""

    def __init__(self, site: dict[str, dict]):
        self._site = site
        self.page = FakePage(site)
        self._returned_main_page = False

    async def new_page(self):
        if not self._returned_main_page:
            self._returned_main_page = True
            return self.page
        return FakePage(self._site)


def _req(method: str, url: str, resource_type: str = "xhr"):
    from types import SimpleNamespace

    return SimpleNamespace(method=method, url=url, resource_type=resource_type)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawl_follows_same_origin_links_breadth_first():
    site = {
        "https://x/": {"links": ["/a", "/b", "https://external.com/evil"]},
        "https://x/a": {"links": ["/c"]},
        "https://x/b": {"links": []},
        "https://x/c": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig(max_depth=3))

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/a", "https://x/b", "https://x/c"}


@pytest.mark.asyncio
async def test_crawl_does_not_guess_auth_required():
    """Regression: `crawl()` used to stamp every discovered endpoint
    `auth_required=True` on the theory that "the crawl was
    authenticated, so everything it found must require auth" -- a
    non-sequitur (a public marketing page reached by a logged-in
    crawl is still public), live-verified to mass-false-positive
    `idor_tests.py`'s TC-050.3 on a real target. `crawl()` no longer
    claims to know this at all; `verify_auth_required()` (a separate,
    real anonymous-probe-based check) is the actual source of truth,
    called by the caller that has an anonymous context available."""
    site = {"https://x/": {"links": []}}
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    assert all(not e.auth_required for e in endpoints)


class _FakeAnonRequest:
    def __init__(self, status_by_url: dict[str, int]):
        self._status_by_url = status_by_url
        self.calls: list[str] = []

    async def get(self, url, timeout=None, max_redirects=None):
        self.calls.append(url)
        resp = AsyncMock()
        resp.status = self._status_by_url.get(url, 200)
        return resp


class _FakeAnonContext:
    def __init__(self, status_by_url: dict[str, int]):
        self.request = _FakeAnonRequest(status_by_url)


@pytest.mark.asyncio
async def test_verify_auth_required_true_for_a_redirect():
    endpoints = [Endpoint(url="https://x/bank/main.jsp", method="GET", endpoint_type="page")]
    anon_context = _FakeAnonContext({"https://x/bank/main.jsp": 302})

    await verify_auth_required(endpoints, anon_context)

    assert endpoints[0].auth_required is True


@pytest.mark.asyncio
async def test_verify_auth_required_true_for_401_or_403():
    endpoints = [
        Endpoint(url="https://x/api/secret", method="GET", endpoint_type="api"),
        Endpoint(url="https://x/forbidden", method="GET", endpoint_type="page"),
    ]
    anon_context = _FakeAnonContext({"https://x/api/secret": 401, "https://x/forbidden": 403})

    await verify_auth_required(endpoints, anon_context)

    assert endpoints[0].auth_required is True
    assert endpoints[1].auth_required is True


@pytest.mark.asyncio
async def test_verify_auth_required_false_for_a_public_page():
    """Regression: this is the exact real-world case that motivated
    the fix -- a public page an authenticated crawl happened to walk
    through must NOT be flagged as requiring auth just because it was
    reachable during that crawl."""
    endpoints = [Endpoint(url="https://x/feedback.jsp", method="GET", endpoint_type="page")]
    anon_context = _FakeAnonContext({"https://x/feedback.jsp": 200})

    await verify_auth_required(endpoints, anon_context)

    assert endpoints[0].auth_required is False


@pytest.mark.asyncio
async def test_verify_auth_required_skips_non_get_endpoints():
    endpoints = [Endpoint(url="https://x/doLogin", method="POST", endpoint_type="form")]
    anon_context = _FakeAnonContext({})

    await verify_auth_required(endpoints, anon_context)

    assert anon_context.request.calls == []
    assert endpoints[0].auth_required is False


@pytest.mark.asyncio
async def test_verify_auth_required_leaves_endpoint_unchanged_on_probe_failure():
    endpoints = [Endpoint(url="https://x/flaky", method="GET", endpoint_type="page", auth_required=True)]

    class _RaisingRequest:
        async def get(self, url, timeout=None, max_redirects=None):
            raise RuntimeError("network error")

    class _RaisingContext:
        request = _RaisingRequest()

    await verify_auth_required(endpoints, _RaisingContext())

    assert endpoints[0].auth_required is True  # untouched, not silently reset


@pytest.mark.asyncio
async def test_crawl_attaches_the_api_sniffer_to_the_form_and_click_probe_pages_too():
    """Regression for a real, confirmed bug: a form's actual network
    request happens on `probe_page` (a form submission), and a
    discovered nav button's on `click_probe_page` (click exploration)
    -- neither is the main BFS `page`. `ApiSniffer` was only ever
    attached to the main page, so the real XHR either of those two
    probe pages fired (e.g. a login form's `POST /rest/user/login`)
    was silently never recorded as an endpoint at all, even though the
    form was correctly identified and genuinely submitted."""
    from stof.crawler import crawler as crawler_module

    attached_pages: list[object] = []
    detached_pages: list[object] = []
    original_attach = crawler_module.ApiSniffer.attach
    original_detach = crawler_module.ApiSniffer.detach

    def _tracking_attach(self, page):
        attached_pages.append(page)
        return original_attach(self, page)

    def _tracking_detach(self, page):
        detached_pages.append(page)
        return original_detach(self, page)

    import unittest.mock

    with unittest.mock.patch.object(crawler_module.ApiSniffer, "attach", _tracking_attach), \
         unittest.mock.patch.object(crawler_module.ApiSniffer, "detach", _tracking_detach):
        site = {"https://x/": {"links": []}}
        context = FakeContext(site)

        await crawl("https://x/", context, CrawlerConfig(submit_forms_with_test_data=True, explore_clickable_navigation=True))

    # Main page + form-submission probe page + click-exploration probe
    # page: three distinct pages, all sniffed.
    assert len(attached_pages) == 3
    assert len(detached_pages) == 3


@pytest.mark.asyncio
async def test_crawl_captures_forms_and_api_calls_alongside_pages():
    site = {
        "https://x/": {
            "links": [],
            "forms": [{"action": "login", "method": "POST", "inputs": [{"name": "u"}]}],
            "api_calls": [_req("GET", "https://x/api/status")],
        }
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    types_found = {e.endpoint_type for e in endpoints}
    assert types_found == {"page", "form", "api"}


# ---------------------------------------------------------------------------
# Passive engine wiring -- opt-in only, must not change default behavior
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawl_without_passive_engine_configured_behaves_unchanged():
    """The default (no `passive_engine` passed) must register no extra
    listeners and return exactly what it always did -- the whole point
    of making this opt-in."""
    from types import SimpleNamespace

    site = {"https://x/": {"links": [], "forms": [], "response": SimpleNamespace(url="https://x/", status=200, headers={"server": "Apache-Coyote/1.1"})}}
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig())

    assert len(endpoints) == 1
    assert endpoints[0].endpoint_type == "page"


@pytest.mark.asyncio
async def test_crawl_feeds_a_configured_passive_engine_from_normal_traffic():
    """No extra request is sent -- the engine only sees the response
    the crawl already received while visiting the page normally."""
    from types import SimpleNamespace

    from stof.passive.engine import PassiveEngine

    site = {"https://x/": {"links": [], "forms": [], "response": SimpleNamespace(url="https://x/", status=200, headers={"server": "Apache-Coyote/1.1"})}}
    context = FakeContext(site)
    engine = PassiveEngine()

    await crawl("https://x/", context, CrawlerConfig(passive_engine=engine))

    assert any(o.kind == "server_version_disclosure" for o in engine.observations)


# ---------------------------------------------------------------------------
# Boundaries — max_depth / max_pages / same-origin
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawl_respects_max_depth():
    site = {
        "https://x/": {"links": ["/a"]},
        "https://x/a": {"links": ["/b"]},
        "https://x/b": {"links": ["/c"]},
        "https://x/c": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig(max_depth=1))

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/a"}


@pytest.mark.asyncio
async def test_crawl_respects_max_pages():
    site = {f"https://x/{i}": {"links": [f"/{i + 1}"]} for i in range(10)}
    context = FakeContext(site)

    endpoints = await crawl("https://x/0", context, CrawlerConfig(max_depth=10, max_pages=3))

    page_urls = [e for e in endpoints if e.endpoint_type == "page"]
    assert len(page_urls) <= 3


@pytest.mark.asyncio
async def test_crawl_never_leaves_same_origin():
    site = {"https://x/": {"links": ["https://evil.example.com/phish", "/safe"]}, "https://x/safe": {"links": []}}
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert urls == {"https://x/", "https://x/safe"}


@pytest.mark.asyncio
async def test_crawl_deduplicates_repeated_links():
    site = {
        "https://x/": {"links": ["/a", "/a", "/a"]},
        "https://x/a": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = [e.url for e in endpoints if e.endpoint_type == "page"]
    assert sorted(page_urls) == ["https://x/", "https://x/a"]


# ---------------------------------------------------------------------------
# Failure resilience — a broken page must not abort the whole crawl
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawl_continues_past_a_page_that_fails_to_load():
    site = {
        "https://x/": {"links": ["/broken", "/ok"]},
        "https://x/ok": {"links": []},
        # "/broken" intentionally absent from `site` -> FakePage.goto raises
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/ok"}


@pytest.mark.asyncio
async def test_crawl_retries_a_transiently_failing_page_and_succeeds():
    site = {
        "https://x/": {"links": ["/flaky"]},
        "https://x/flaky": {"links": [], "fail_times": 1},  # fails once, then succeeds
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig(retries_per_page=1))

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/flaky"}
    # goto was attempted twice for the flaky page: once failed, once succeeded
    assert context.page.goto_calls.count("https://x/flaky") == 2


@pytest.mark.asyncio
async def test_crawl_gives_up_after_exhausting_retries():
    site = {
        "https://x/": {"links": ["/always-broken"]},
        "https://x/always-broken": {"links": [], "fail_times": 99},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig(retries_per_page=2))

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/"}
    # 1 initial attempt + 2 retries = 3 total attempts
    assert context.page.goto_calls.count("https://x/always-broken") == 3


@pytest.mark.asyncio
async def test_crawl_watchdog_recovers_from_a_page_that_never_resolves():
    """Regression: live-verified against a real target (AltoroMutual's
    careers page) that `page.goto()`'s own `timeout` can fail to fire
    at all if the underlying CDP connection is wedged, hanging the
    whole crawl indefinitely. `page_watchdog_s` is the hard backstop --
    this must complete promptly instead of hanging the test suite."""
    site = {
        "https://x/": {"links": ["/wedged", "/ok"]},
        "https://x/wedged": {"hang": True},
        "https://x/ok": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await asyncio.wait_for(
        crawl("https://x/", context, CrawlerConfig(retries_per_page=0, page_watchdog_s=0.05)),
        timeout=5,
    )

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/ok"}  # /wedged never completed, but didn't block the rest


@pytest.mark.asyncio
async def test_crawl_exclude_path_patterns_skips_matching_links():
    """The reliable mitigation for a page that destabilizes the
    browser (see CrawlerConfig.page_watchdog_s's own docstring): an
    operator-configured substring match keeps the crawler from ever
    visiting it, instead of hoping a timeout recovers cleanly."""
    site = {
        "https://x/": {"links": ["/careers?job=Teller", "/ok"]},
        "https://x/careers?job=Teller": {"links": []},
        "https://x/ok": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig(exclude_path_patterns=("job=",)))

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/ok"}
    assert "https://x/careers?job=Teller" not in context.page.goto_calls


@pytest.mark.asyncio
async def test_crawl_does_not_duplicate_page_endpoint_after_a_retry():
    """A failed attempt appends to page_endpoints before the exception
    fires (goto succeeds, the forms scan fails afterwards) -- the retry
    must not leave that stray entry behind once the next attempt
    succeeds cleanly, or the page would show up twice."""
    site = {
        "https://x/": {"links": ["/flaky"]},
        "https://x/flaky": {"links": [], "evaluate_fail_times": 1},  # fails once, then succeeds
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig(retries_per_page=2))

    page_urls = [e.url for e in endpoints if e.endpoint_type == "page"]
    assert page_urls.count("https://x/flaky") == 1


@pytest.mark.asyncio
async def test_crawl_continues_when_a_later_page_evaluate_fails_mid_page():
    """Regression test: a real crawl of demo.testfire.net hit a PDF link
    that made goto() raise "Download is starting" -- caught fine -- but
    then the *next* page's evaluate() call failed with "Execution
    context was destroyed", which used to crash the whole crawl because
    only goto() was wrapped in a try/except, not the forms/links calls
    that follow it.

    goto() itself succeeds here (only the later evaluate() call fails),
    so that page still counts as discovered -- it just won't have form
    endpoints. What this test actually pins down is that the crawl
    doesn't abort: a *sibling* page queued alongside it still gets
    visited, which it wouldn't if the exception had propagated out of
    the while loop."""
    site = {
        "https://x/": {"links": ["/broken-evaluate", "/ok"]},
        "https://x/broken-evaluate": {"links": [], "evaluate_error": True},
        "https://x/ok": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/broken-evaluate", "https://x/ok"}
    assert all(e.endpoint_type != "form" for e in endpoints)  # forms scan never completed


# ---------------------------------------------------------------------------
# Input validation — ignored href schemes / non-HTML downloads
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawl_skips_download_file_links_without_visiting_them():
    site = {
        "https://x/": {"links": ["/report.pdf", "/archive.zip", "/real"]},
        "https://x/real": {"links": []},
        # "/report.pdf" / "/archive.zip" deliberately absent from `site`:
        # error-recovery alone would also make page_urls come out right
        # if the crawler *attempted and failed* to visit them, so this
        # test asserts on goto_calls directly to prove they were skipped
        # proactively, not merely recovered from after the fact.
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/real"}
    assert not any(call.endswith((".pdf", ".zip")) for call in context.page.goto_calls)


@pytest.mark.asyncio
async def test_crawl_ignores_non_navigable_hrefs():
    site = {
        "https://x/": {"links": ["javascript:void(0)", "mailto:a@b.com", "#section", "", "/real"]},
        "https://x/real": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/real"}


# ---------------------------------------------------------------------------
# SPA hash-routing (Angular HashLocationStrategy etc., e.g. Juice Shop) --
# regression coverage for the crawl-coverage gap found via the Juice Shop
# benchmark: a hash-routed nav used to be entirely invisible to the
# crawler, discovering only the bare root page.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawl_follows_hash_route_links():
    site = {
        "https://x/": {"links": ["#/search", "#/login"]},
        "https://x/#/search": {"links": []},
        "https://x/#/login": {"links": [], "forms": [{"action": "doLogin", "method": "POST", "inputs": [{"name": "u"}]}]},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/#/search", "https://x/#/login"}
    form_urls = {e.url for e in endpoints if e.endpoint_type == "form"}
    assert "https://x/doLogin" in form_urls


@pytest.mark.asyncio
async def test_crawl_follows_hashbang_route_links():
    site = {
        "https://x/": {"links": ["#!/products"]},
        "https://x/#!/products": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert "https://x/#!/products" in page_urls


@pytest.mark.asyncio
async def test_crawl_still_ignores_plain_in_page_anchor_hrefs():
    """A bare "#section" anchor jump (not a route) must still be
    skipped -- only a "#/..."/"#!/..."-shaped href is a real route."""
    site = {
        "https://x/": {"links": ["#section", "#top"]},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/"}


@pytest.mark.asyncio
async def test_crawl_deduplicates_repeated_hash_route_links():
    site = {
        "https://x/": {"links": ["#/search", "#/search"]},
        "https://x/#/search": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = [e.url for e in endpoints if e.endpoint_type == "page"]
    assert sorted(page_urls) == ["https://x/", "https://x/#/search"]


@pytest.mark.asyncio
async def test_crawl_waits_for_network_idle_after_a_hash_route_change():
    """goto() to a hash-only URL resolves as soon as the hash itself
    changes -- before the SPA's own JS has rendered the new view. The
    crawler must give it a chance to settle before scanning the DOM,
    or a route's real links/forms are missed even though the route was
    reached."""
    site = {
        "https://x/": {"links": ["#/search"]},
        "https://x/#/search": {"links": ["/found-after-render"]},
        "https://x/found-after-render": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert "https://x/found-after-render" in page_urls


@pytest.mark.asyncio
async def test_crawl_recovers_when_network_idle_never_settles_after_hash_route():
    """A route whose page keeps polling (never goes network-idle) must
    not hang or crash the crawl -- the wait is best-effort, not a hard
    requirement to proceed."""
    site = {
        "https://x/": {"links": ["#/live"]},
        "https://x/#/live": {"links": [], "networkidle_hang": True},
    }
    context = FakeContext(site)

    endpoints = await asyncio.wait_for(
        crawl("https://x/", context, CrawlerConfig(page_watchdog_s=0.2, retries_per_page=0)),
        timeout=5,
    )

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert "https://x/" in page_urls


# ---------------------------------------------------------------------------
# Click-based navigation discovery -- routes reachable only via a
# `<button>`/icon element with client-side routing behind it, never a
# plain `<a href>`. Deliberately framework-generic: no hardcoded route
# name, only structural signals (button/role=button/routerlink/onclick).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawl_discovers_a_route_only_reachable_by_clicking_a_button():
    site = {
        "https://x/": {
            "links": [],
            "clickable": [{"text": "Account", "leads_to": "https://x/#/login"}],
        },
        "https://x/#/login": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert "https://x/#/login" in page_urls


@pytest.mark.asyncio
async def test_crawl_click_exploration_skips_destructive_looking_buttons():
    site = {
        "https://x/": {
            "links": [],
            "clickable": [{"text": "Delete my account", "leads_to": "https://x/deleted"}],
        },
        "https://x/deleted": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert "https://x/deleted" not in page_urls


@pytest.mark.asyncio
async def test_crawl_click_exploration_falls_back_to_aria_label_when_text_is_empty():
    """Icon-only buttons (no visible text) commonly carry the label as
    aria-label/title instead -- the danger-word check must still see it."""
    site = {
        "https://x/": {
            "links": [],
            "clickable": [{"text": "", "aria-label": "Log out", "leads_to": "https://x/bye"}],
        },
        "https://x/bye": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert "https://x/bye" not in page_urls


@pytest.mark.asyncio
async def test_crawl_click_exploration_skips_invisible_candidates():
    site = {
        "https://x/": {
            "links": [],
            "clickable": [{"text": "Hidden menu item", "visible": False, "leads_to": "https://x/hidden-target"}],
        },
        "https://x/hidden-target": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert "https://x/hidden-target" not in page_urls


@pytest.mark.asyncio
async def test_crawl_click_exploration_respects_max_candidates_cap():
    clickable = [{"text": f"item{i}", "leads_to": f"https://x/item{i}"} for i in range(5)]
    site = {"https://x/": {"links": [], "clickable": clickable}}
    for spec in clickable:
        site[spec["leads_to"]] = {"links": []}
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig(max_click_candidates_per_page=2))

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    discovered_items = page_urls & {spec["leads_to"] for spec in clickable}
    assert len(discovered_items) <= 2


@pytest.mark.asyncio
async def test_crawl_click_exploration_reaches_both_account_and_basket_within_budget():
    """Regression for a real bug introduced by the commerce-priority
    fix itself: ranking ONLY commerce actions first just traded one
    blind spot for another -- against real Juice Shop, several
    "Add to Basket" buttons (one per product) filled the entire
    high-priority budget and crowded out the single "Account" icon
    click that discovers the login route, so JS-01/JS-03/JS-08 (all
    login-dependent) went from caught to missed in the very next run.
    Both families must be reachable together within one ordinary
    budget, since the account icon (header, appears first in the DOM)
    should still rank ahead of later product-grid buttons."""
    clickable = [
        {"text": "Account", "leads_to": "https://x/#/login"},
        {"text": "nav item 1", "leads_to": "https://x/nav1"},
        {"text": "nav item 2", "leads_to": "https://x/nav2"},
        {"text": "Add to Basket", "leads_to": "https://x/rest/basket/1"},
        {"text": "Add to Basket", "leads_to": "https://x/rest/basket/2"},
    ]
    site = {"https://x/": {"links": [], "clickable": clickable}}
    for spec in clickable:
        site.setdefault(spec["leads_to"], {"links": []})
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig(max_click_candidates_per_page=2))

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert "https://x/#/login" in page_urls
    assert any(url.startswith("https://x/rest/basket/") for url in page_urls)


@pytest.mark.asyncio
async def test_crawl_click_exploration_prioritizes_commerce_actions_within_a_tight_budget():
    """Regression for the real Juice Shop gap: a page can have far more
    clickable elements (nav icons, etc.) than the per-page click budget
    allows -- DOM order alone means a commerce action buried later never
    gets a chance to be clicked, so whatever resource it creates (a
    basket, in Juice Shop's case) is never discovered at all, and IDOR
    testing against it has nothing to work with. A tight budget of 1
    must still reach the "Add to Basket" button ahead of five earlier,
    unrelated nav buttons."""
    clickable = [
        {"text": "nav item 1", "leads_to": "https://x/nav1"},
        {"text": "nav item 2", "leads_to": "https://x/nav2"},
        {"text": "nav item 3", "leads_to": "https://x/nav3"},
        {"text": "nav item 4", "leads_to": "https://x/nav4"},
        {"text": "nav item 5", "leads_to": "https://x/nav5"},
        {"text": "Add to Basket", "leads_to": "https://x/rest/basket/1"},
    ]
    site = {"https://x/": {"links": [], "clickable": clickable}}
    for spec in clickable:
        site[spec["leads_to"]] = {"links": []}
    context = FakeContext(site)

    # cap=2, 6 total candidates -- the scan phase (bounded to
    # max_candidates * a fixed multiplier) covers all 6 here, so this
    # isolates the actual thing under test (does ranking put the
    # commerce action first) rather than the separate, already-covered
    # "does the scan phase even reach a deeply-buried candidate" case.
    endpoints = await crawl("https://x/", context, CrawlerConfig(max_click_candidates_per_page=2))

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert "https://x/rest/basket/1" in page_urls
    # Only one of the five nav items can also fit in the remaining
    # budget slot -- at least four must be crowded out by the
    # higher-priority commerce action.
    assert sum(1 for i in range(1, 6) if f"https://x/nav{i}" in page_urls) <= 1


@pytest.mark.asyncio
async def test_crawl_click_exploration_settles_before_scanning_a_hash_route_page():
    """Regression for a real, confirmed source of run-to-run flakiness:
    click-exploration used to scan a hash-routed page for clickable
    candidates immediately after goto() returns, before the SPA's own
    JS had necessarily finished reacting to the hashchange event and
    rendering the view -- the exact same page could yield a different
    candidate set (and therefore a different discovered-endpoint set)
    from one run to the next, purely from timing luck. This is a
    regression test for the fix, not a functional one: it just proves
    the settle-wait actually happens for a hash-routed page before
    click-exploration's own navigation, matching what the main BFS
    loop already does for every page it visits."""
    site = {"https://x/#/products": {"links": [], "clickable": []}}
    context = FakeContext(site)
    click_probe = FakePage(site)

    # First new_page() -> main BFS page, second (with form-submission
    # probing off) -> the click-exploration page.
    context.new_page = AsyncMock(side_effect=[context.page, click_probe])

    await crawl("https://x/#/products", context, CrawlerConfig(submit_forms_with_test_data=False))

    assert "https://x/#/products" in click_probe.wait_for_load_state_calls


@pytest.mark.asyncio
async def test_crawl_click_exploration_disabled_by_config():
    site = {
        "https://x/": {
            "links": [],
            "clickable": [{"text": "Account", "leads_to": "https://x/#/login"}],
        },
        "https://x/#/login": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig(explore_clickable_navigation=False))

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert "https://x/#/login" not in page_urls


@pytest.mark.asyncio
async def test_crawl_click_exploration_recovers_from_a_failing_click():
    """One candidate raising on click() must not abort discovery of the
    rest, or of the crawl as a whole."""
    site = {
        "https://x/": {
            "links": [],
            "clickable": [
                {"text": "broken", "click_error": True},
                {"text": "works", "leads_to": "https://x/reached"},
            ],
        },
        "https://x/reached": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/reached"}


@pytest.mark.asyncio
async def test_crawl_click_exploration_falls_back_to_force_click_when_blocked_by_an_overlay():
    """Regression for the real Juice Shop finding: a normal click waits
    for the element to actually receive pointer events, which never
    happens when an unrelated overlay (cookie-consent banner, a
    leftover CDK backdrop) sits on top of the whole page -- every
    candidate on every page timed out this way, discovering nothing.
    A `force=True` retry bypasses that specific check and must recover
    the route anyway."""
    site = {
        "https://x/": {
            "links": [],
            "clickable": [{"text": "Account", "click_error": True, "force_click_succeeds": True, "leads_to": "https://x/#/login"}],
        },
        "https://x/#/login": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert "https://x/#/login" in page_urls


@pytest.mark.asyncio
async def test_crawl_click_exploration_skips_the_baseline_reset_after_the_last_candidate():
    """Efficiency regression: resetting back to `page_url` (a full
    navigation, plus a settle wait for a hash-routed page) only exists
    to protect the NEXT candidate's baseline -- after the last
    candidate there is no next one, so paying that cost is pure waste.
    Two candidates, cap=2: exactly 2 clicks, and the reset-goto count
    for the click-probe page must be one less than the click count
    (one reset between the two clicks, none after the second)."""
    clickable = [
        {"text": "item1", "leads_to": "https://x/item1"},
        {"text": "item2", "leads_to": "https://x/item2"},
    ]
    site = {
        "https://x/": {"links": [], "clickable": clickable},
        "https://x/item1": {"links": []},
        "https://x/item2": {"links": []},
    }
    context = FakeContext(site)
    click_probe = FakePage(site)
    context.new_page = AsyncMock(side_effect=[context.page, click_probe])

    await crawl("https://x/", context, CrawlerConfig(submit_forms_with_test_data=False, max_click_candidates_per_page=2))

    # 1 initial load + 1 reset between the two candidates = 2 total
    # goto() calls to "https://x/" on the click-probe page -- NOT 3
    # (which is what an unconditional reset after every candidate,
    # including the last, would produce).
    assert click_probe.goto_calls.count("https://x/") == 2


@pytest.mark.asyncio
async def test_crawl_click_exploration_follows_a_menu_trigger_to_a_revealed_login_item():
    """Regression for the real root cause behind JS-01/JS-03/JS-08
    flakiness: Juice Shop's "Account" header button doesn't navigate
    anywhere by itself -- it's a menu trigger (`aria-label="Show/hide
    account menu"`) that reveals a "Login" menu item which was
    INVISIBLE until the trigger was clicked. The primary click loop
    alone (single click, check for URL change) records "nothing
    happened" and moves on; the bounded one-level follow-up must catch
    this and land on the revealed item's own destination."""
    clickable = [
        {"text": "Login", "aria-label": "Go to login page", "visible": False, "leads_to": "https://x/#/login"},
        {"text": "Account", "aria-label": "Show/hide account menu", "reveals": [0]},
    ]
    site = {"https://x/": {"links": [], "clickable": clickable}, "https://x/#/login": {"links": []}}
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert "https://x/#/login" in page_urls


@pytest.mark.asyncio
async def test_crawl_click_exploration_dismisses_a_dialog_triggered_by_a_click():
    site = {
        "https://x/": {
            "links": [],
            "clickable": [{"text": "confirm", "dialog_message": "Are you sure?", "leads_to": "https://x/confirmed"}],
        },
        "https://x/confirmed": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await asyncio.wait_for(crawl("https://x/", context), timeout=5)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert "https://x/confirmed" in page_urls


# ---------------------------------------------------------------------------
# Session safety — regression tests for the demo.testfire.net finding:
# following a logout link mid-crawl silently kills the authenticated
# session for every page visited afterward, with no exception raised.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crawl_never_follows_a_logout_link():
    site = {
        "https://x/": {"links": ["/logout.jsp", "/account", "/Sign-Out", "/safe"]},
        "https://x/account": {"links": []},
        "https://x/safe": {"links": []},
        # "/logout.jsp" and "/Sign-Out" deliberately absent from `site`:
        # if the crawler attempted them, FakePage.goto would 404 and
        # error-recovery would still make page_urls look right, so this
        # test asserts on goto_calls directly, proving they were never
        # even attempted -- the same pattern used for download links.
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert page_urls == {"https://x/", "https://x/account", "https://x/safe"}
    assert not any("logout" in call.lower() or "sign-out" in call.lower() for call in context.page.goto_calls)


@pytest.mark.asyncio
async def test_crawl_records_the_landed_url_not_the_requested_url_after_a_redirect():
    """The core bug: a page that silently redirects (e.g. to a login
    page because the session was somehow lost) must never be recorded
    under the URL it was *supposed* to be, since that misrepresents what
    was actually captured -- the forms/content that follow are for
    whatever page was really landed on."""
    site = {
        "https://x/": {"links": ["/protected"]},
        "https://x/protected": {"redirect_to": "https://x/login", "links": []},
        "https://x/login": {"links": [], "forms": [{"action": "doLogin", "method": "POST", "inputs": [{"name": "u"}]}]},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    page_urls = {e.url for e in endpoints if e.endpoint_type == "page"}
    assert "https://x/protected" not in page_urls
    assert "https://x/login" in page_urls
    form_urls = {e.url for e in endpoints if e.endpoint_type == "form"}
    assert "https://x/doLogin" in form_urls


@pytest.mark.asyncio
async def test_crawl_retry_cleanup_matches_landed_url_after_redirect():
    """Regression for a bug introduced by the landed-url fix itself: the
    retry loop's "undo the partial append before retrying" cleanup used
    to compare against the *requested* URL, which never matches when a
    redirect happened -- silently leaving a stray duplicate page entry
    behind once the retry succeeded."""
    site = {
        "https://x/": {"links": ["/flaky"]},
        "https://x/flaky": {"redirect_to": "https://x/landed", "links": []},
        # evaluate() checks self.url, which is the *landed* url after a
        # redirect -- the fail-once counter has to live there, not on
        # the originally-requested "/flaky" entry.
        "https://x/landed": {"links": [], "evaluate_fail_times": 1},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context, CrawlerConfig(retries_per_page=2))

    page_urls = [e.url for e in endpoints if e.endpoint_type == "page"]
    assert page_urls.count("https://x/landed") == 1


@pytest.mark.asyncio
async def test_crawl_does_not_record_off_origin_redirect_as_endpoint():
    """A same-origin link can still redirect off-site (e.g. Juice
    Shop's own `/redirect?to=...` open redirect, confirmed live against
    the real target). The destination must never be recorded as one of
    *this* target's endpoints, and its own links must never be followed
    -- vulnerability modules and Burp's Active Scan both treat
    everything in the returned list as fair game to send test/attack
    traffic to, and a stray third-party URL would mean probing a real
    external site without authorization."""
    site = {
        "https://x/": {"links": ["/redirect?to=https://evil.example/"]},
        "https://x/redirect?to=https://evil.example/": {
            "redirect_to": "https://evil.example/",
            "links": ["/should-not-be-followed"],
        },
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    assert not any("evil.example" in e.url for e in endpoints)
    # goto_calls legitimately includes the *requesting* URL, whose own
    # query string names "evil.example" as the redirect target -- what
    # must never happen is actually navigating there for its own sake.
    assert not any(call.startswith("https://evil.example") for call in context.page.goto_calls)


@pytest.mark.asyncio
async def test_crawl_resolves_links_against_landed_url_after_same_origin_redirect():
    """Relative hrefs on the page actually reached must resolve against
    where the browser landed, not the URL that was originally
    requested -- resolving against the wrong base (a real bug found
    live: a redirect through a `/redirect?to=` page silently produced
    same-origin-*looking* URLs, all bogus, none of which were really
    discovered) silently corrupts the endpoint list."""
    site = {
        "https://x/": {"links": ["/go?to=/sub/"]},
        "https://x/go?to=/sub/": {"redirect_to": "https://x/sub/page"},
        "https://x/sub/page": {"links": ["sibling"]},
        "https://x/sub/sibling": {"links": []},
    }
    context = FakeContext(site)

    endpoints = await crawl("https://x/", context)

    urls = {e.url for e in endpoints}
    assert "https://x/sub/sibling" in urls
